//go:generate go run pkg/codegen/cleanup/main.go
//go:generate /bin/rm -rf pkg/generated
//go:generate go run pkg/codegen/main.go

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/rancher/wrangler/v3/pkg/kubeconfig"
	"github.com/rancher/wrangler/v3/pkg/signals"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"

	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	operatorapiv1 "github.com/rancher/compliance-operator/pkg/apis/compliance.cattle.io/v1"
	operator "github.com/rancher/compliance-operator/pkg/securityscan"

	// Automatically sets fallback trusted x509 roots, in case they are
	// not available at runtime. This is required to establish trust
	// when deployed into a scratch container.
	_ "golang.org/x/crypto/x509roots/fallback"

	// Embed a copy of the timezone database, so that it does not depend
	// on it being available at runtime.
	_ "time/tzdata"

	corev1 "k8s.io/api/core/v1"
)

var (
	Version                       = "v0.0.0-dev"
	GitCommit                     = "HEAD"
	kubeConfig                    string
	threads                       int
	name                          string
	metricsPort                   string
	alertSeverity                 string
	debug                         bool
	securityScanImage             string
	securityScanImageTag          string
	clusterName                   string
	securityScanJobTolerationsVal string
)

func main() {
	app := &cli.Command{
		Name:    "compliance-operator",
		Version: fmt.Sprintf("%s (%s)", Version, GitCommit),
		Usage:   "compliance-operator needs help!",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "kubeconfig",
				Sources:     cli.EnvVars("KUBECONFIG"),
				Destination: &kubeConfig,
			},
			&cli.IntFlag{
				Name:        "threads",
				Sources:     cli.EnvVars("OPERATOR_THREADS"),
				Value:       2,
				Destination: &threads,
			},
			&cli.StringFlag{
				Name:        "name",
				Sources:     cli.EnvVars("OPERATOR_NAME"),
				Value:       "compliance-operator",
				Destination: &name,
			},
			&cli.StringFlag{
				Name:        "security-scan-image",
				Sources:     cli.EnvVars("SECURITY_SCAN_IMAGE"),
				Value:       "rancher/security-scan",
				Destination: &securityScanImage,
			},
			&cli.StringFlag{
				Name:        "security-scan-image-tag",
				Sources:     cli.EnvVars("SECURITY_SCAN_IMAGE_TAG"),
				Value:       "latest",
				Destination: &securityScanImageTag,
			},
			&cli.StringFlag{
				Name:        "metrics_port",
				Sources:     cli.EnvVars("METRICS_PORT"),
				Value:       "8080",
				Destination: &metricsPort,
			},
			&cli.BoolFlag{
				Name:        "debug",
				Sources:     cli.EnvVars("OPERATOR_DEBUG"),
				Destination: &debug,
			},
			&cli.StringFlag{
				Name:        "alertSeverity",
				Sources:     cli.EnvVars("ALERTS_SEVERITY"),
				Value:       "warning",
				Destination: &alertSeverity,
			},
			&cli.StringFlag{
				Name:        "clusterName",
				Sources:     cli.EnvVars("CLUSTER_NAME"),
				Value:       "",
				Destination: &clusterName,
			},
			&cli.StringFlag{
				Name:        "security-scan-job-tolerations",
				Sources:     cli.EnvVars("SECURITY_SCAN_JOB_TOLERATIONS"),
				Value:       "",
				Destination: &securityScanJobTolerationsVal,
			},
			&cli.BoolFlag{
				Name:    "alertEnabled",
				Sources: cli.EnvVars("ALERTS_ENABLED"),
			},
		},
		Action: run,
	}

	if err := app.Run(context.TODO(), os.Args); err != nil {
		logrus.Fatal(err)
	}
}

func run(ctx context.Context, c *cli.Command) error {
	logrus.Info("Starting compliance-operator")

	handler := signals.SetupSignalHandler()
	go func() {
		<-handler
		ctx.Done()
	}()

	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	}
	kubeConfig = c.String("kubeconfig")
	threads = c.Int("threads")
	securityScanImage = c.String("security-scan-image")
	securityScanImageTag = c.String("security-scan-image-tag")
	name = c.String("name")

	securityScanJobTolerations := []corev1.Toleration{{
		Operator: corev1.TolerationOpExists,
	}}

	securityScanJobTolerationsVal = c.String("security-scan-job-tolerations")

	if securityScanJobTolerationsVal != "" {
		err := json.Unmarshal([]byte(securityScanJobTolerationsVal), &securityScanJobTolerations)
		if err != nil {
			logrus.Fatalf("invalid value received for security-scan-job-tolerations flag:%s", err.Error())
		}
	}

	kubeConfig, err := kubeconfig.GetNonInteractiveClientConfig(kubeConfig).ClientConfig()
	if err != nil {
		logrus.Fatalf("failed to find kubeconfig: %v", err)
	}

	imgConfig := &operatorapiv1.ScanImageConfig{
		SecurityScanImage:    securityScanImage,
		SecurityScanImageTag: securityScanImageTag,
		AlertSeverity:        alertSeverity,
		ClusterName:          clusterName,
		AlertEnabled:         c.Bool("alertEnabled"),
	}

	if err := validateConfig(imgConfig); err != nil {
		logrus.Fatalf("Error starting compliance-operator: %v", err)
	}

	ctl, err := operator.NewController(ctx, kubeConfig, operatorapiv1.ClusterScanNS, name, imgConfig, securityScanJobTolerations)
	if err != nil {
		logrus.Fatalf("Error building controller: %s", err.Error())
	}

	if err := ctl.Start(ctx, threads, 2*time.Hour); err != nil {
		logrus.Fatalf("Error starting: %v", err)
	}

	http.Handle("/metrics", promhttp.Handler())
	if err := http.ListenAndServe(":"+metricsPort, nil); err != nil {
		log.Fatal(err)
	}

	<-handler
	ctx.Done()
	logrus.Info("Registered Compliance controller")
	return nil
}

func validateConfig(imgConfig *operatorapiv1.ScanImageConfig) error {
	if imgConfig.SecurityScanImage == "" {
		return errors.New("No Security-Scan Image specified")
	}
	return nil
}
