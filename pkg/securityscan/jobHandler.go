package securityscan

import (
	"context"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/rancher/security-scan/pkg/kb-summarizer/report"
	reportLibrary "github.com/rancher/security-scan/pkg/kb-summarizer/report"
	batchctlv1 "github.com/rancher/wrangler/v3/pkg/generated/controllers/batch/v1"

	"time"

	operatorapi "github.com/rancher/compliance-operator/pkg/apis/compliance.cattle.io"
	v1 "github.com/rancher/compliance-operator/pkg/apis/compliance.cattle.io/v1"
	"github.com/rancher/compliance-operator/pkg/xccdf"
	"github.com/rancher/wrangler/v3/pkg/name"
)

var sonobuoyWorkerLabel = map[string]string{"sonobuoy-plugin": "rancher-kube-bench"}

// job events (successful completions) should remove the job after validatinf Done annotation and Output CM
func (c *Controller) handleJobs(ctx context.Context) error {
	scans := c.complianceFactory.Compliance().V1().ClusterScan()
	reports := c.complianceFactory.Compliance().V1().ClusterScanReport()
	jobs := c.batchFactory.Batch().V1().Job()

	jobs.OnChange(ctx, c.Name, func(_ string, obj *batchv1.Job) (*batchv1.Job, error) {
		if obj == nil || obj.DeletionTimestamp != nil {
			return obj, nil
		}
		jobSelector := labels.SelectorFromSet(labels.Set{
			operatorapi.LabelController: c.Name,
		})
		// avoid commandeering jobs from other controllers
		if obj.Labels == nil || !jobSelector.Matches(labels.Set(obj.Labels)) {
			return obj, nil
		}
		// identify the scan object for this job
		scanName, ok := obj.Labels[operatorapi.LabelClusterScan]
		if !ok {
			// malformed, just delete it and move on
			logrus.Errorf("malformed scan, deleting the job %v", obj.Name)
			return obj, c.deleteJob(jobs, obj, metav1.DeletePropagationBackground)
		}
		// get the scan being run
		scan, err := scans.Get(scanName, metav1.GetOptions{})
		switch {
		case errors.IsNotFound(err):
			// scan is gone, delete
			logrus.Errorf("scan gone, deleting the job %v", obj.Name)
			return obj, c.deleteJob(jobs, obj, metav1.DeletePropagationBackground)
		case err != nil:
			return obj, err
		}

		// if the scan has completed then delete the job
		if v1.ClusterScanConditionComplete.IsTrue(scan) {
			if !v1.ClusterScanConditionFailed.IsTrue(scan) {
				logrus.Infof("Marking ClusterScanConditionAlerted for scan: %v", scanName)
				v1.ClusterScanConditionAlerted.Unknown(scan)
			}
			scan.Status.ObservedGeneration = scan.Generation
			c.setClusterScanStatusDisplay(scan)

			if scan.Spec.ScheduledScanConfig != nil && scan.Spec.ScheduledScanConfig.CronSchedule != "" {
				err := c.rescheduleScan(scan)
				if err != nil {
					return obj, fmt.Errorf("error rescheduling scan: %w", err)
				}
				err = c.purgeOldClusterScanReports(scan)
				if err != nil {
					return obj, fmt.Errorf("error purging old ClusterScanReports: %w", err)
				}
			}
			err := c.deleteJob(jobs, obj, metav1.DeletePropagationBackground)
			if err != nil {
				return obj, fmt.Errorf("error deleting job: %w", err)
			}
			err = c.ensureCleanup(scan)
			if err != nil {
				return obj, err
			}
			//update scan
			_, err = scans.UpdateStatus(scan)
			if err != nil {
				return nil, fmt.Errorf("error updating condition of cluster scan object: %v", scanName)
			}
			c.currentScanName = ""
			return obj, nil
		}

		// If the job itself has failed (e.g. ActiveDeadlineSeconds exceeded) and the scan
		// hasn't been updated yet, mark it failed so it doesn't stall in running forever.
		if !v1.ClusterScanConditionRunCompleted.IsTrue(scan) {
			for _, cond := range obj.Status.Conditions {
				if cond.Type == batchv1.JobFailed && cond.Status == corev1.ConditionTrue {
					scanCopy := scan.DeepCopy()
					v1.ClusterScanConditionRunCompleted.True(scanCopy)
					v1.ClusterScanConditionFailed.True(scanCopy)
					v1.ClusterScanConditionFailed.Message(scanCopy, fmt.Sprintf("Scan job failed: %s", cond.Message))
					c.setClusterScanStatusDisplay(scanCopy)
					_, err = scans.UpdateStatus(scanCopy)
					if err != nil {
						return nil, fmt.Errorf("error updating scan status for failed job %v: %v", obj.Name, err)
					}
					logrus.Infof("Marking scan %v as failed due to job failure: %v", scanName, cond.Message)
					jobs.Enqueue(obj.Namespace, obj.Name)
					return obj, nil
				}
			}
		}

		if v1.ClusterScanConditionRunCompleted.IsTrue(scan) {
			scancopy := scan.DeepCopy()

			if !v1.ClusterScanConditionFailed.IsTrue(scan) {
				summary, report, err := c.getScanResults(ctx, scan)
				if err != nil {
					return nil, fmt.Errorf("error %v reading results of cluster scan object: %v", err, scanName)
				}
				scancopy.Status.Summary = summary
				_, err = reports.Create(report)
				if err != nil {
					return nil, fmt.Errorf("error %v saving clusterscanreport object", err)
				}
			}
			v1.ClusterScanConditionComplete.True(scancopy)
			/* update scan */
			_, err = scans.UpdateStatus(scancopy)
			if err != nil {
				return nil, fmt.Errorf("error updating condition of scan object: %v", scanName)
			}
			logrus.Infof("Marking ClusterScanConditionComplete for scan: %v", scanName)
			jobs.Enqueue(obj.Namespace, obj.Name)
		}
		return obj, nil
	})
	return nil
}

func (c *Controller) deleteJob(jobController batchctlv1.JobController, job *batchv1.Job, deletionPropagation metav1.DeletionPropagation) error {
	return jobController.Delete(job.Namespace, job.Name, &metav1.DeleteOptions{PropagationPolicy: &deletionPropagation})
}

func (c *Controller) getScanResults(ctx context.Context, scan *v1.ClusterScan) (*v1.ClusterScanSummary, *v1.ClusterScanReport, error) {
	configmaps := c.coreFactory.Core().V1().ConfigMap()
	//get the output configmap and create a report
	outputConfigName := strings.Join([]string{`scan-output-for`, scan.Name}, "-")
	cm, err := configmaps.Cache().Get(v1.ClusterScanNS, outputConfigName)
	if err != nil {
		return nil, nil, fmt.Errorf("jobHandler: Updated: error fetching configmap %v: %v", outputConfigName, err)
	}
	outputBytes := []byte(cm.Data[v1.DefaultScanOutputFileName])
	scanSummary, err := c.getScanSummary(outputBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("jobHandler: Updated: error getting report from configmap %v: %v", outputConfigName, err)
	}
	if scanSummary == nil {
		return nil, nil, fmt.Errorf("jobHandler: Updated: error: got empty report from configmap %v", outputConfigName)
	}

	scanReport, err := c.createClusterScanReport(ctx, outputBytes, scan)
	if err != nil {
		return nil, nil, fmt.Errorf("jobHandler: Updated: error getting report from configmap %v: %v", outputConfigName, err)
	}

	return scanSummary, scanReport, nil
}

func (c *Controller) getScanSummary(outputBytes []byte) (*v1.ClusterScanSummary, error) {
	r, err := report.Get(outputBytes)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, nil
	}
	scanSummary := &v1.ClusterScanSummary{
		Total:         r.Total,
		Pass:          r.Pass,
		Fail:          r.Fail,
		Skip:          r.Skip,
		Warn:          r.Warn,
		NotApplicable: r.NotApplicable,
	}
	return scanSummary, nil
}


func (c *Controller) createClusterScanReport(ctx context.Context, outputBytes []byte, scan *v1.ClusterScan) (*v1.ClusterScanReport, error) {
	scanReport := &v1.ClusterScanReport{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: name.SafeConcatName("scan-report", scan.Name, scan.Spec.ScanProfileName) + "-",
		},
	}
	profile, err := c.getClusterScanProfile(ctx, scan)
	if err != nil {
		return nil, fmt.Errorf("Error %v loading v1.ClusterScanProfile for name %w", scan.Spec.ScanProfileName, err)
	}
	scanReport.Spec.BenchmarkVersion = profile.Spec.BenchmarkVersion
	scanReport.Spec.LastRunTimestamp = time.Now().String()

	data, err := reportLibrary.GetJSONBytes(outputBytes)
	if err != nil {
		return nil, fmt.Errorf("Error %w loading scan report json bytes", err)
	}
	scanReport.Spec.ReportJSON = string(data[:])

	if scan.Spec.OutputFormat == v1.OutputFormatXCCDF {
		benchmark, err := c.getClusterScanBenchmark(profile)
		if err != nil {
			return nil, fmt.Errorf("Error %w loading ClusterScanBenchmark for XCCDF report", err)
		}
		stigChecks := make(map[string]xccdf.StigCheckMetadata, len(benchmark.Spec.StigChecks))
		for k, v := range benchmark.Spec.StigChecks {
			stigChecks[k] = xccdf.StigCheckMetadata{
				RuleID:   v.RuleID,
				Version:  v.Version,
				Severity: v.Severity,
				FixID:    v.FixID,
				CheckID:  v.CheckID,
				CCI:      v.CCI,
			}
		}
		clusterName := scan.Spec.ClusterName
		if clusterName == "" {
			clusterName = benchmark.Spec.BenchmarkMetadata.ClusterName
		}
		meta := xccdf.BenchmarkMetadata{
			ClusterName:         clusterName,
			BenchmarkID:         benchmark.Spec.BenchmarkMetadata.BenchmarkID,
			Title:               benchmark.Spec.BenchmarkMetadata.Title,
			Creator:             benchmark.Spec.BenchmarkMetadata.Creator,
			Publisher:           benchmark.Spec.BenchmarkMetadata.Publisher,
			Contributor:         benchmark.Spec.BenchmarkMetadata.Contributor,
			Source:              benchmark.Spec.BenchmarkMetadata.Source,
			Description:         benchmark.Spec.BenchmarkMetadata.Description,
			NoticeID:            benchmark.Spec.BenchmarkMetadata.NoticeID,
			Notice:              benchmark.Spec.BenchmarkMetadata.Notice,
			FrontMatter:         benchmark.Spec.BenchmarkMetadata.FrontMatter,
			RearMatter:          benchmark.Spec.BenchmarkMetadata.RearMatter,
			ReferenceHref:       benchmark.Spec.BenchmarkMetadata.ReferenceHref,
			PlainTextID:         benchmark.Spec.BenchmarkMetadata.PlainTextID,
			PlainText:           benchmark.Spec.BenchmarkMetadata.PlainText,
			Platform:            benchmark.Spec.BenchmarkMetadata.Platform,
			ReferenceTitle:      benchmark.Spec.BenchmarkMetadata.ReferenceTitle,
			ReferenceType:       benchmark.Spec.BenchmarkMetadata.ReferenceType,
			ReferenceSubject:    benchmark.Spec.BenchmarkMetadata.ReferenceSubject,
			ReferenceIdentifier: benchmark.Spec.BenchmarkMetadata.ReferenceIdentifier,
			CheckHref:           benchmark.Spec.BenchmarkMetadata.CheckHref,
			CheckName:           benchmark.Spec.BenchmarkMetadata.CheckName,
			StigChecks:          stigChecks,
		}
		nodes, err := c.kcs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			logrus.Warnf("failed to list nodes for XCCDF target facts: %v", err)
		} else {
			for _, node := range nodes.Items {
				for _, addr := range node.Status.Addresses {
					switch addr.Type {
					case corev1.NodeInternalIP:
						meta.TargetAddresses = append(meta.TargetAddresses, addr.Address)
						meta.TargetFacts = append(meta.TargetFacts, xccdf.Fact{
							Name:  "urn:xccdf:fact:asset:identifier:ipv4",
							Type:  "string",
							Value: addr.Address,
						})
					case corev1.NodeHostName:
						meta.TargetFacts = append(meta.TargetFacts, xccdf.Fact{
							Name:  "urn:xccdf:fact:asset:identifier:host_name",
							Type:  "string",
							Value: addr.Address,
						})
					}
				}
			}
			if c.KubernetesVersion != "" {
				meta.TargetFacts = append(meta.TargetFacts, xccdf.Fact{
					Name:  "urn:xccdf:fact:asset:identifier:kubernetes-version",
					Type:  "string",
					Value: c.KubernetesVersion,
				})
			}
		}
		xccdfBytes, err := xccdf.FromJSON(outputBytes, profile.Spec.BenchmarkVersion, meta)
		if err != nil {
			return nil, fmt.Errorf("Error %w generating XCCDF report", err)
		}
		scanReport.Spec.ReportXCCDF = string(xccdfBytes)
	}

	ownerRef := metav1.OwnerReference{
		APIVersion: "compliance.cattle.io/v1",
		Kind:       "ClusterScan",
		Name:       scan.Name,
		UID:        scan.GetUID(),
	}
	scanReport.ObjectMeta.OwnerReferences = append(scanReport.ObjectMeta.OwnerReferences, ownerRef)

	return scanReport, nil
}

func (c *Controller) ensureCleanup(scan *v1.ClusterScan) error {
	var err error
	// Delete the dameonset
	dsPrefix := "sonobuoy-rancher-kube-bench-daemon-set"
	dsList, err := c.daemonsetCache.List(v1.ClusterScanNS, labels.Set(sonobuoyWorkerLabel).AsSelector())
	if err != nil {
		return fmt.Errorf("compliance: ensureCleanup: error listing daemonsets: %w", err)
	}
	for _, ds := range dsList {
		if !strings.HasPrefix(ds.Name, dsPrefix) {
			continue
		}
		if e := c.daemonsets.Delete(v1.ClusterScanNS, ds.Name, &metav1.DeleteOptions{}); e != nil && !errors.IsNotFound(e) {
			return fmt.Errorf("compliance: ensureCleanup: error deleting daemonset %v: %v", ds.Name, e)
		}
	}

	// Delete the pod
	podPrefix := name.SafeConcatName("security-scan-runner", scan.Name)
	podList, err := c.podCache.List(v1.ClusterScanNS, labels.Set(SonobuoyMasterLabel).AsSelector())
	if err != nil {
		return fmt.Errorf("compliance: ensureCleanup: error listing pods: %w", err)
	}
	for _, pod := range podList {
		if !strings.HasPrefix(pod.Name, podPrefix) {
			continue
		}
		if e := c.pods.Delete(v1.ClusterScanNS, pod.Name, &metav1.DeleteOptions{}); e != nil && !errors.IsNotFound(e) {
			return fmt.Errorf("compliance: ensureCleanup: error deleting pod %v: %w", pod.Name, e)
		}
	}

	// Delete cms
	cms, err := c.configMapCache.List(v1.ClusterScanNS, labels.NewSelector())
	if err != nil {
		return fmt.Errorf("compliance: ensureCleanup: error listing cm: %w", err)
	}
	for _, cm := range cms {
		if !strings.Contains(cm.Name, scan.Name) {
			continue
		}

		if e := c.configmaps.Delete(v1.ClusterScanNS, cm.Name, &metav1.DeleteOptions{}); e != nil && !errors.IsNotFound(e) {
			return fmt.Errorf("compliance: ensureCleanup: error deleting cm %v: %w", cm.Name, e)
		}
	}

	return err
}

