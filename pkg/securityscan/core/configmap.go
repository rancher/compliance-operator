package core

import (
	"bytes"
	_ "embed" // nolint
	"encoding/json"
	"text/template"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8Yaml "k8s.io/apimachinery/pkg/util/yaml"

	wcorev1 "github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	"github.com/rancher/wrangler/v3/pkg/name"

	operatorapiv1 "github.com/rancher/compliance-operator/pkg/apis/compliance.cattle.io/v1"
)

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

func NewConfigMaps(clusterscan *operatorapiv1.ClusterScan, clusterscanprofile *operatorapiv1.ClusterScanProfile, clusterscanbenchmark *operatorapiv1.ClusterScanBenchmark, _ string, imageConfig *operatorapiv1.ScanImageConfig, configmapsClient wcorev1.ConfigMapController) (cmMap map[string]*corev1.ConfigMap, err error) {
	cmMap = make(map[string]*corev1.ConfigMap)

	configdata := map[string]interface{}{
		"namespace":        operatorapiv1.ClusterScanNS,
		"name":             name.SafeConcatName(operatorapiv1.ClusterScanConfigMap, clusterscan.Name),
		"runName":          name.SafeConcatName("security-scan-runner", clusterscan.Name),
		"appName":          "rancher-compliance",
		"advertiseAddress": operatorapiv1.ClusterScanService,
		// security-scan ships the sonobuoy binary at /sonobuoy, so it is also
		// used as the image of the Sonobuoy worker sidecar.
		"workerImage": imageConfig.SecurityScanImage + ":" + imageConfig.SecurityScanImageTag,
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
