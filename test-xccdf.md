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

On Rancher UI, initiate a compliance scan with the rke2-stig-1.31-rgs profile.

XCCDF generation now happens client-side in the Rancher dashboard. After the scan
completes, use the dashboard's XCCDF download button to export the report.