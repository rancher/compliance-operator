#!/usr/bin/env bash
# Prepares the charts of a release for the ship-family-staged action of rancher/charts. It
# makes the two charts of the Rancher catalog from a checkout of the release, in <output dir>:
#
#   rancher-compliance      the chart in chart/, as it is
#   rancher-compliance-crd  the CRDs in crds/, as a chart of their own
#
# The action stamps, checks, packages and pushes the copies, so the source stays as it is.
# The annotations of chart/Chart.yaml, among them catalog.cattle.io/rancher-version and
# catalog.cattle.io/kube-version, are not changed here: they say which Rancher and
# Kubernetes versions a release supports, and the catalog needs both bounds in each.
#
# Usage: prepare-charts.sh <release checkout> <output dir>
#   e.g. prepare-charts.sh release "$RUNNER_TEMP/charts"
set -euo pipefail

REL=${1:?usage: $0 <release checkout> <output dir>}
OUT=${2:?usage: $0 <release checkout> <output dir>}

for file in chart/Chart.yaml chart/values.yaml crds; do
  if [ ! -e "$REL/$file" ]; then
    echo "Error: there is no $file in $REL" >&2
    exit 1
  fi
done
shopt -s nullglob
crds=("$REL"/crds/*.yaml)
if [ ${#crds[@]} -eq 0 ]; then
  echo "Error: there is no CRD in $REL/crds" >&2
  exit 1
fi

rm -rf "$OUT/rancher-compliance" "$OUT/rancher-compliance-crd"
mkdir -p "$OUT/rancher-compliance-crd/templates"
cp -r "$REL/chart" "$OUT/rancher-compliance"

# The CRDs are a chart of their own in the catalog, installed before the chart. The version
# is a placeholder, because the action stamps the final one.
cp "${crds[@]}" "$OUT/rancher-compliance-crd/templates/"
cat >"$OUT/rancher-compliance-crd/Chart.yaml" <<'YAML'
apiVersion: v2
name: rancher-compliance-crd
description: Installs the CRDs for rancher-compliance.
version: "0"
type: application
annotations:
  catalog.cattle.io/certified: rancher
  catalog.cattle.io/hidden: "true"
  catalog.cattle.io/namespace: compliance-operator-system
  catalog.cattle.io/release-name: rancher-compliance-crd
YAML
