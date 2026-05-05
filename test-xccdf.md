Build and push image to registry: 
```bash
docker buildx build --platform linux/amd64 \  -f package/Dockerfile \                                                              
  -t <private-registry>/rancher/compliance-operator:dev \
  --push .
```

or:

```bash
docker build --platform linux/amd64 \                               
  -f package/Dockerfile \
  -t <private-registry>/rancher/compliance-operator:dev .
```
```bash=
docker push <private-registry>/rancher/compliance-operator:dev
```

Install compliance operator on a downstream RKE2 cluster. 

Set image and pull policy:

```bash=
kubectl edit deployment compliance-operator -n <namespace>
```

```yaml
spec:
  template:
    spec:
      containers:
      - name: compliance-operator
        image: harbor.local/rancher/compliance-operator:dev
        imagePullPolicy: Always
```

Apply updated STIG profile:
```bash
kubectl apply -f rke2-stig-1.31-rgs.yaml
```

Apply CRDs:
```bash
kubectl apply -f crds/clusterscan.yaml
kubectl apply -f crds/clusterscanreport.yaml
kubectl apply -f crds/clusterscanbenchmark.yaml
```

After setting image pull policy to always, delete pods to force refresh:
```bash
kubectl delete pod -n compliance-operator-system --all
```

On Rancher UI, initiate complaince scan with the rke2-stig-1.31-rgs profile. Click edit as yaml and add `outputFormat: xccdf` under `spec:`.

Retrieve clusterscanreport and export to file:
```bash
kubectl get clusterscanreport -n compliance-operator-system
```
```bash
kubectl get clusterscanreport <scan-report> -n compliance-operator-system -o jsonpath='{.spec.reportXCCDF}' > ~/Downloads/scan-report-xccdf.xml   
```
Can optionally upload the xml file to a tool like STIG Manager to check output. 