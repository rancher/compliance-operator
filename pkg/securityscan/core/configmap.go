package core

import (
	"bytes"
	_ "embed" // nolint
	"encoding/json"
	"fmt"
	"strings"
	"text/template"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8Yaml "k8s.io/apimachinery/pkg/util/yaml"

	wcorev1 "github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	"github.com/rancher/wrangler/v3/pkg/name"

	operatorapiv1 "github.com/rancher/compliance-operator/pkg/apis/compliance.cattle.io/v1"
)

var requiredPaths = map[string]string{
	"var-rancher": "/var/lib/rancher",
	"etc-rancher": "/etc/rancher",
	"etc-cni":     "/etc/cni/net.d",
	"var-cni":     "/var/lib/cni",
	"var-log":     "/var/log",
	"run-log":     "/run/log",
	"etc-kubelet": "/etc/kubernetes/kubelet",
	"var-kubelet": "/var/lib/kubelet",
}

//go:embed templates/pluginConfig.template
var pluginConfigTemplate string

//go:embed templates/scanConfig.template
var scanConfigTemplate string

type OverrideSkipInfoData struct {
	Skip map[string][]string `json:"skip"`
}

const (
	CurrentBenchmarkKey = "current"
	ConfigFileName      = "config.json"
)

func NewConfigMaps(clusterscan *operatorapiv1.ClusterScan, clusterscanprofile *operatorapiv1.ClusterScanProfile, clusterscanbenchmark *operatorapiv1.ClusterScanBenchmark, _ string, imageConfig *operatorapiv1.ScanImageConfig,
	configmapsClient wcorev1.ConfigMapController, customScanHostPaths []string) (cmMap map[string]*corev1.ConfigMap, err error) {
	cmMap = make(map[string]*corev1.ConfigMap)

	configdata := map[string]interface{}{
		"namespace":        operatorapiv1.ClusterScanNS,
		"name":             name.SafeConcatName(operatorapiv1.ClusterScanConfigMap, clusterscan.Name),
		"runName":          name.SafeConcatName("security-scan-runner", clusterscan.Name),
		"appName":          "rancher-compliance",
		"advertiseAddress": operatorapiv1.ClusterScanService,
		"sonobuoyImage":    imageConfig.SonobuoyImage + ":" + imageConfig.SonobuoyImageTag,
		"sonobuoyVersion":  imageConfig.SonobuoyImageTag,
	}
	configcm, err := generateConfigMap(clusterscan, "scanConfig.template", scanConfigTemplate, configdata)
	if err != nil {
		return cmMap, err
	}
	cmMap["configcm"] = configcm

	var isCustomBenchmark bool
	customBenchmarkConfigMapName := ""
	customBenchmarkConfigMapData := make(map[string]string)
	if clusterscanbenchmark.Spec.CustomBenchmarkConfigMapName != "" {
		isCustomBenchmark = true
		customcm, err := getCustomBenchmarkConfigMap(clusterscanbenchmark, clusterscan, configmapsClient)
		if err != nil {
			return cmMap, err
		}
		customBenchmarkConfigMapData = customcm.Data
		customBenchmarkConfigMapName = customcm.Name
	}
	hostPathVolumes, hostPathVolumeMounts := pluginConfigHostPathVolumesData(customScanHostPaths)
	plugindata := map[string]interface{}{
		"namespace":                    operatorapiv1.ClusterScanNS,
		"name":                         name.SafeConcatName(operatorapiv1.ClusterScanPluginsConfigMap, clusterscan.Name),
		"runName":                      name.SafeConcatName("security-scan-runner", clusterscan.Name),
		"appName":                      "rancher-compliance",
		"serviceaccount":               operatorapiv1.ClusterScanSA,
		"securityScanImage":            imageConfig.SecurityScanImage + ":" + imageConfig.SecurityScanImageTag,
		"benchmarkVersion":             clusterscanprofile.Spec.BenchmarkVersion,
		"isCustomBenchmark":            isCustomBenchmark,
		"configDir":                    operatorapiv1.CustomBenchmarkBaseDir,
		"customBenchmarkConfigMapName": customBenchmarkConfigMapName,
		"customBenchmarkConfigMapData": customBenchmarkConfigMapData,
		"hostPathVolumes":              hostPathVolumes,
		"hostPathVolumeMounts":         hostPathVolumeMounts,
	}
	plugincm, err := generateConfigMap(clusterscan, "pluginConfig.template", pluginConfigTemplate, plugindata)
	if err != nil {
		return cmMap, err
	}
	cmMap["plugincm"] = plugincm

	var skipConfigcm *corev1.ConfigMap
	if clusterscanprofile.Spec.SkipTests != nil && len(clusterscanprofile.Spec.SkipTests) > 0 {
		//create user skip config map as well
		// create the cm
		skipDataBytes, err := getOverrideSkipInfoData(clusterscanprofile.Spec.SkipTests)
		if err != nil {
			return cmMap, err
		}
		skipConfigcm = getConfigMapObject(getOverrideConfigMapName(clusterscan), string(skipDataBytes))
		cmMap["skipConfigcm"] = skipConfigcm
	}

	return cmMap, nil
}

func generateConfigMap(clusterscan *operatorapiv1.ClusterScan, name string, text string, data map[string]interface{}) (*corev1.ConfigMap, error) {
	configcm := &corev1.ConfigMap{}

	obj, err := parseTemplate(clusterscan, name, text, data)
	if err != nil {
		return nil, err
	}

	if err := obj.Decode(&configcm); err != nil {
		return nil, err
	}
	return configcm, nil
}

func parseTemplate(_ *operatorapiv1.ClusterScan, name string, text string, data map[string]interface{}) (*k8Yaml.YAMLOrJSONDecoder, error) {
	cmTemplate, err := template.New(name).Parse(text)
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	err = cmTemplate.Execute(&b, data)
	if err != nil {
		return nil, err
	}

	return k8Yaml.NewYAMLOrJSONDecoder(&b, 1000), nil
}

func getOverrideConfigMapName(cs *operatorapiv1.ClusterScan) string {
	return name.SafeConcatName(operatorapiv1.ClusterScanUserSkipConfigMap, cs.Name)
}

func getOverrideSkipInfoData(skip []string) ([]byte, error) {
	s := OverrideSkipInfoData{Skip: map[string][]string{CurrentBenchmarkKey: skip}}
	return json.Marshal(s)
}

func getConfigMapObject(cmName, data string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: operatorapiv1.ClusterScanNS,
		},
		Data: map[string]string{
			ConfigFileName: data,
		},
	}
}

func getCustomBenchmarkConfigMap(benchmark *operatorapiv1.ClusterScanBenchmark, clusterscan *operatorapiv1.ClusterScan, configmapsClient wcorev1.ConfigMapController) (*corev1.ConfigMap, error) {
	if benchmark.Spec.CustomBenchmarkConfigMapName == "" {
		return nil, nil
	}
	userConfigmap, err := configmapsClient.Get(benchmark.Spec.CustomBenchmarkConfigMapNamespace, benchmark.Spec.CustomBenchmarkConfigMapName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if benchmark.Spec.CustomBenchmarkConfigMapNamespace == operatorapiv1.ClusterScanNS {
		return userConfigmap, nil
	}

	// Copy the configmap to ClusterScanNS so that the security scan pod
	// can find it for volume mount this will be cleaned up after scan
	// job finishes.
	configmapCopy := corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name.SafeConcatName(operatorapiv1.CustomBenchmarkConfigMap, clusterscan.Name),
			Namespace: operatorapiv1.ClusterScanNS,
		},
		Data: userConfigmap.Data,
	}
	return configmapsClient.Create(&configmapCopy)
}

func pluginConfigHostPathVolumesData(customScanHostPaths []string) ([]*corev1.Volume, []*corev1.VolumeMount) {
	volumes := make([]*corev1.Volume, 0, len(requiredPaths)+len(customScanHostPaths))
	volumeMounts := make([]*corev1.VolumeMount, 0, len(requiredPaths)+len(customScanHostPaths))
	hostPaths := make(map[string]bool, len(requiredPaths))

	// Add required volumes
	for name, path := range requiredPaths {
		path = strings.TrimSuffix(path, "/")
		volumes = append(volumes, &corev1.Volume{
			Name: name,
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{Path: path},
			},
		})
		volumeMounts = append(volumeMounts, &corev1.VolumeMount{Name: name, MountPath: path, ReadOnly: true})
		hostPaths[path] = true
	}

	// Add custom volumes if they are not already included
	for idx, path := range customScanHostPaths {
		if !hostPaths[path] {
			path = strings.TrimSuffix(path, "/")
			name := fmt.Sprintf("custom-volume-%d", idx)
			volumes = append(volumes, &corev1.Volume{
				Name: name,
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{Path: path},
				},
			})
			volumeMounts = append(volumeMounts, &corev1.VolumeMount{Name: name, MountPath: path, ReadOnly: true})
			hostPaths[path] = true
		}
	}

	return volumes, volumeMounts
}
