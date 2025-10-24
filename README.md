# compliance-operator [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/rancher/compliance-operator/badge)](https://scorecard.dev/viewer/?uri=github.com/rancher/compliance-operator)

The compliance-operator enables running Compliance security scans on a Kubernetes cluster and generate compliance reports that can be downloaded.
Benchmarks tests and the execution logic lives on [rancher/security-scan].

## Building

`make`


## Running
1. Install the custom resource definitions:
- `kubectl apply -f crds/`
2. Install the operator
`./bin/compliance-operator`


## Branches and Releases
### General information
The current branch strategy for `rancher/compliance-operator` is laid out below:

| Branch                | Tag      |Security-Scan          | Rancher                   |
|-----------------------|----------|-----------------------|---------------------------|
| `main`                | `head`   |`main` branch (`head`)`| `main` branch (`head`)    |
| `release/v1.2`        | `v1.2.x` |`v0.7.x`               | `v2.12.x`                 |

Note that it aligns with Rancher Manager releases to maximize compatibility
within the ecosystem. This includes k8s dependencies that the Rancher release
aims to support, meaning that compliance-operator should use the same k8s minor release
that the Rancher release line it aims to support.

Active development takes place against `main`. Release branches are only used for
bug fixes and security-related dependency bumps.

Refer to the [Support Compatibility Matrix](https://www.suse.com/suse-rancher/support-matrix/)
for official compatibility information.

### How future release branches should be generated
Follow these guidelines when releasing new branches:
1. Name convention to be used: `release/v1.x.x`.
2. Update the [Branch and Releases](https://github.com/rancher/compliance-operator#branches-and-releases) table with the new branches and remove the no longer needed branches.

## License
Copyright (c) 2025 SUSE LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

[rancher/security-scan]: https://github.com/rancher/security-scan
