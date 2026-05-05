package v1

import (
	condition "github.com/rancher/compliance-operator/pkg/condition"
	"github.com/rancher/wrangler/v3/pkg/genericcondition"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ClusterProviderRKE = "rke"
	ClusterProviderEKS = "eks"
	ClusterProviderGKE = "gke"
	ClusterProviderAKS = "aks"
	ClusterProviderK3s = "k3s"

	OutputFormatJSON  = "json"
	OutputFormatXCCDF = "xccdf"

	ClusterScanNS                      = "compliance-operator-system"
	ClusterScanSA                      = "compliance-scan-serviceaccount"
	ClusterScanConfigMap               = "compliance-config-cm"
	ClusterScanPluginsConfigMap        = "compliance-plugins-cm"
	ClusterScanUserSkipConfigMap       = "compliance-user-skip-cm"
	DefaultClusterScanProfileConfigMap = "default-clusterscanprofiles"
	ClusterScanService                 = "service-rancher-compliance"
	DefaultScanOutputFileName          = "output.json"
	DefaultRetention                   = 3
	DefaultCronSchedule                = "0 0 * * *"
	CustomBenchmarkBaseDir             = "/etc/kbs/custombenchmark/cfg"
	CustomBenchmarkConfigMap           = "compliance-bmark-cm"

	ClusterScanConditionCreated      = condition.Cond("Created")
	ClusterScanConditionPending      = condition.Cond("Pending")
	ClusterScanConditionRunCompleted = condition.Cond("RunCompleted")
	ClusterScanConditionComplete     = condition.Cond("Complete")
	ClusterScanConditionFailed       = condition.Cond("Failed")
	ClusterScanConditionAlerted      = condition.Cond("Alerted")
	ClusterScanConditionReconciling  = condition.Cond("Reconciling")
	ClusterScanConditionStalled      = condition.Cond("Stalled")

	ClusterScanFailOnWarning = "fail"
	ClusterScanPassOnWarning = "pass"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ClusterScan struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterScanSpec   `json:"spec"`
	Status ClusterScanStatus `yaml:"status" json:"status,omitempty"`
}

type ClusterScanSpec struct {
	// scan profile to use
	ScanProfileName string `json:"scanProfileName,omitempty"`
	//config for scheduled scan
	ScheduledScanConfig *ScheduledScanConfig `yaml:"scheduled_scan_config" json:"scheduledScanConfig,omitempty"`
	// Specify if tests with "warn" output should be counted towards scan failure
	ScoreWarning string `yaml:"score_warning" json:"scoreWarning,omitempty"`
	// OutputFormat specifies the format of the generated scan report. Supported values are "json" (default) and "xccdf".
	OutputFormat string `json:"outputFormat,omitempty"`
	// ClusterName sets the XCCDF <target> element in the generated report. Only used when outputFormat is "xccdf".
	ClusterName string `json:"clusterName,omitempty"`
}

type ClusterScanStatus struct {
	Display                *ClusterScanStatusDisplay           `json:"display,omitempty"`
	LastRunTimestamp       string                              `yaml:"last_run_timestamp" json:"lastRunTimestamp"`
	LastRunScanProfileName string                              `json:"lastRunScanProfileName,omitempty"`
	Summary                *ClusterScanSummary                 `json:"summary,omitempty"`
	ObservedGeneration     int64                               `json:"observedGeneration"`
	Conditions             []genericcondition.GenericCondition `json:"conditions,omitempty"`
	NextScanAt             string                              `json:"NextScanAt"`
	ScanAlertingRuleName   string                              `json:"ScanAlertingRuleName"`
}

type ClusterScanStatusDisplay struct {
	State         string `json:"state"`
	Message       string `json:"message"`
	Error         bool   `json:"error"`
	Transitioning bool   `json:"transitioning"`
}

type ClusterScanSummary struct {
	Total         int `json:"total"`
	Pass          int `json:"pass"`
	Fail          int `json:"fail"`
	Skip          int `json:"skip"`
	Warn          int `json:"warn"`
	NotApplicable int `json:"notApplicable"`
}

type ScheduledScanConfig struct {
	// Cron Expression for Schedule
	CronSchedule string `yaml:"cron_schedule" json:"cronSchedule,omitempty"`
	// Number of past scans to keep
	RetentionCount int `yaml:"retentionCount" json:"retentionCount,omitempty"`
	//configure the alerts to be sent out
	ScanAlertRule *ClusterScanAlertRule `json:"scanAlertRule,omitempty"`
}

type ClusterScanAlertRule struct {
	AlertOnComplete bool `json:"alertOnComplete,omitempty"`
	AlertOnFailure  bool `json:"alertOnFailure,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ClusterScanBenchmark struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ClusterScanBenchmarkSpec `json:"spec"`
}

type BenchmarkMetadataSpec struct {
	// BenchmarkID sets the XCCDF Benchmark id attribute (e.g. "RGS_RKE2_STIG").
	BenchmarkID string `json:"benchmarkId,omitempty"`
	// Title sets the XCCDF Benchmark title element.
	Title string `json:"title,omitempty"`
	// ClusterName overrides the XCCDF <target> element. When empty the operator
	// falls back to the CLUSTER_NAME env var, then to node names from the report.
	ClusterName string `json:"clusterName,omitempty"`
	Creator       string `json:"creator,omitempty"`
	Publisher     string `json:"publisher,omitempty"`
	Contributor   string `json:"contributor,omitempty"`
	Source        string `json:"source,omitempty"`
	Description   string `json:"description,omitempty"`
	NoticeID      string `json:"noticeId,omitempty"`
	Notice        string `json:"notice,omitempty"`
	FrontMatter   string `json:"frontMatter,omitempty"`
	RearMatter    string `json:"rearMatter,omitempty"`
	ReferenceHref string `json:"referenceHref,omitempty"`
	PlainTextID   string `json:"plainTextId,omitempty"`
	PlainText     string `json:"plainText,omitempty"`
	Platform      string `json:"platform,omitempty"`
	// Rule-level reference fields (same for all rules within a STIG benchmark).
	ReferenceTitle      string `json:"referenceTitle,omitempty"`
	ReferenceType       string `json:"referenceType,omitempty"`
	ReferenceSubject    string `json:"referenceSubject,omitempty"`
	ReferenceIdentifier string `json:"referenceIdentifier,omitempty"`
	// Check content ref fields shared across all rules.
	CheckHref string `json:"checkHref,omitempty"`
	CheckName string `json:"checkName,omitempty"`
}

// StigCheckSpec holds per-check STIG metadata for a single STIG group (e.g. V-254553).
type StigCheckSpec struct {
	RuleID   string   `json:"ruleId,omitempty"`
	Version  string   `json:"version,omitempty"`
	Severity string   `json:"severity,omitempty"`
	FixID    string   `json:"fixId,omitempty"`
	CheckID  string   `json:"checkId,omitempty"`
	CCI      []string `json:"cci,omitempty"`
}

type ClusterScanBenchmarkSpec struct {
	ClusterProvider      string `json:"clusterProvider,omitempty"`
	MinKubernetesVersion string `json:"minKubernetesVersion,omitempty"`
	MaxKubernetesVersion string `json:"maxKubernetesVersion,omitempty"`

	CustomBenchmarkConfigMapName      string `json:"customBenchmarkConfigMapName,omitempty"`
	CustomBenchmarkConfigMapNamespace string `json:"customBenchmarkConfigMapNamespace,omitempty"`

	BenchmarkMetadata BenchmarkMetadataSpec        `json:"benchmarkMetadata,omitempty"`
	StigChecks        map[string]StigCheckSpec      `json:"stigChecks,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ClusterScanProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ClusterScanProfileSpec `json:"spec"`
}

type ClusterScanProfileSpec struct {
	BenchmarkVersion string   `json:"benchmarkVersion,omitempty"`
	SkipTests        []string `json:"skipTests,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ClusterScanReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ClusterScanReportSpec `json:"spec"`
}

type ClusterScanReportSpec struct {
	BenchmarkVersion string `json:"benchmarkVersion,omitempty"`
	LastRunTimestamp string `yaml:"last_run_timestamp" json:"lastRunTimestamp"`
	ReportJSON       string `json:"reportJSON"`
	// ReportXCCDF contains the scan results in XCCDF 1.2 XML format. Populated when the scan's outputFormat is "xccdf".
	ReportXCCDF string `json:"reportXCCDF,omitempty"`
}

type ScanImageConfig struct {
	SecurityScanImage    string
	SecurityScanImageTag string
	SonobuoyImage        string
	SonobuoyImageTag     string
	AlertSeverity        string
	ClusterName          string
	AlertEnabled         bool
}
