#!/bin/bash
# Prepares the charts of the rancher-compliance family for the ship-family-staged
# action of rancher/charts (charts v2, cargueiro):
#
#   <output dir>/rancher-compliance      a copy of chart/, with the appVersion and
#                                         the compliance-operator image tag set to
#                                         the release tag.
#   <output dir>/rancher-compliance-crd  a chart made from crds/, which until now
#                                         was generated on the rancher/charts side.
#
# The action stamps, checks, packages and pushes these folders, so the source
# stays as it is. The chart version is left to the action: cargueiro chart-version
# works it out from the rancher-version annotation, the appVersion and the
# versions already in the staging registry (1XY.Z.0+upA.B.C).
#
# The security-scan and kuberlr-kubectl images are pinned in chart/ and are not
# changed here.
#
# Usage: prepare-charts.sh <tag> <output dir>
#   e.g. prepare-charts.sh v1.6.0-rc.9 "$RUNNER_TEMP/charts"
#
# Run from the repository root.
set -euo pipefail

TAG=${1:?usage: $0 <tag> <output dir>}
OUT_DIR=${2:?usage: $0 <tag> <output dir>}

if ! [[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then
  echo "Error: tag $TAG must look like vX.Y.Z or vX.Y.Z-rc.N" >&2
  exit 1
fi

MAIN_DIR="$OUT_DIR/rancher-compliance"
CRD_DIR="$OUT_DIR/rancher-compliance-crd"
rm -rf "$MAIN_DIR" "$CRD_DIR"
mkdir -p "$OUT_DIR"

cp -r chart "$MAIN_DIR"
sed -i \
  -e "s|^appVersion:.*|appVersion: ${TAG}|" \
  -e "s|image: rancher/compliance-operator:.*|image: rancher/compliance-operator:${TAG}|" \
  "$MAIN_DIR/Chart.yaml"
# Only the tag right after the compliance-operator repository.
sed -i -e "/repository: rancher\/compliance-operator$/{n;s|tag: .*|tag: ${TAG}|}" "$MAIN_DIR/values.yaml"

for want in "appVersion: ${TAG}" "image: rancher/compliance-operator:${TAG}"; do
  if ! grep -qF "$want" "$MAIN_DIR/Chart.yaml"; then
    echo "Error: could not set '$want' in $MAIN_DIR/Chart.yaml" >&2
    exit 1
  fi
done
if ! grep -A1 'repository: rancher/compliance-operator$' "$MAIN_DIR/values.yaml" | grep -qF "tag: ${TAG}"; then
  echo "Error: could not set the compliance-operator tag in $MAIN_DIR/values.yaml" >&2
  exit 1
fi

# The CRD chart, as rancher/charts made it from packages/rancher-compliance/templates/crd-template.
# The version is a placeholder: the action stamps the version of the family.
mkdir -p "$CRD_DIR/templates"
cp crds/*.yaml "$CRD_DIR/templates/"
cat > "$CRD_DIR/Chart.yaml" <<'EOF'
apiVersion: v1
version: 0.0.0
description: Installs the CRDs for rancher-compliance.
name: rancher-compliance-crd
type: application
annotations:
  catalog.cattle.io/hidden: "true"
  catalog.cattle.io/release-name: rancher-compliance-crd
  catalog.cattle.io/certified: rancher
  catalog.cattle.io/namespace: compliance-operator-system
EOF
cat > "$CRD_DIR/README.md" <<'EOF'
# rancher-compliance-crd
A Rancher chart that installs the CRDs used by rancher-compliance.
EOF
