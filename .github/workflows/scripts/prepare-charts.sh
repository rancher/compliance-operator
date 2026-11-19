#!/bin/bash
# Prepares the charts of the rancher-compliance family for the ship-family-staged
# action of rancher/charts (charts v2, cargueiro):
#
#   <output dir>/rancher-compliance      a copy of charts/rancher-compliance, with
#                                         the appVersion and the compliance-operator
#                                         image tag set to the release tag.
#   <output dir>/rancher-compliance-crd  a copy of charts/rancher-compliance-crd.
#
# The action stamps, checks, packages and pushes these folders, so the source
# stays as it is. The chart version is left to the action: cargueiro chart-version
# works it out from the rancher-version annotation, the appVersion and the
# versions already in the staging registry (1XY.Z.0+upA.B.C). cargueiro stamp also
# writes the helm.sh/images annotation from the images of values.yaml, so the
# source charts must not have one.
#
# The security-scan and kuberlr-kubectl images are pinned in values.yaml and are
# not changed here.
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

SRC_MAIN=charts/rancher-compliance
SRC_CRD=charts/rancher-compliance-crd
for src in "$SRC_MAIN" "$SRC_CRD"; do
  if [ ! -f "$src/Chart.yaml" ]; then
    echo "Error: $src/Chart.yaml not found, run this script from the repository root" >&2
    exit 1
  fi
  if grep -q 'helm\.sh/images:' "$src/Chart.yaml"; then
    echo "Error: remove the helm.sh/images annotation from $src/Chart.yaml, cargueiro writes it from values.yaml" >&2
    exit 1
  fi
done

MAIN_DIR="$OUT_DIR/rancher-compliance"
CRD_DIR="$OUT_DIR/rancher-compliance-crd"
rm -rf "$MAIN_DIR" "$CRD_DIR"
mkdir -p "$OUT_DIR"

cp -r "$SRC_MAIN" "$MAIN_DIR"
sed -i -e "s|^appVersion:.*|appVersion: ${TAG}|" "$MAIN_DIR/Chart.yaml"
# Only the tag right after the compliance-operator repository.
sed -i -e "/repository: rancher\/compliance-operator$/{n;s|tag: .*|tag: ${TAG}|}" "$MAIN_DIR/values.yaml"

if ! grep -qxF "appVersion: ${TAG}" "$MAIN_DIR/Chart.yaml"; then
  echo "Error: could not set 'appVersion: ${TAG}' in $MAIN_DIR/Chart.yaml" >&2
  exit 1
fi
if ! grep -A1 'repository: rancher/compliance-operator$' "$MAIN_DIR/values.yaml" | grep -qF "tag: ${TAG}"; then
  echo "Error: could not set the compliance-operator tag in $MAIN_DIR/values.yaml" >&2
  exit 1
fi

# The version is a placeholder: the action stamps the version of the family.
cp -r "$SRC_CRD" "$CRD_DIR"
