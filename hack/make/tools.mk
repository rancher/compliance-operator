TOOLS_BIN := $(shell mkdir -p build/tools && realpath build/tools)
OS_NAME = $(shell uname -s | tr A-Z a-z)
OS_ARCH = $(shell uname -m)

ifeq ($(OS_ARCH),x86_64)
	OS_ARCH = amd64
endif
ifeq ($(OS_ARCH),aarch64)
	OS_ARCH = arm64
endif

# On Linux, the tools are installed from the Prime RPM repository built by
# rancher/cowboy-builder-specs, which rebuilds them with the latest Go patch
# version. zypper verifies the packages against the GPG key kept in
# rancher/rancher. The packages are Linux-only, so other OSes download the
# upstream releases instead.
RPM_PKGS_REPO := https://rpm.rancher.io/pkgs/prime
RPM_PKGS_KEY := https://raw.githubusercontent.com/rancher/rancher/refs/heads/main/rancher-rpm-pkgs.key
RPM_PKGS_IMAGE := registry.suse.com/bci/bci-base:16.0

# install-rpm-pkg installs the RPM package $(1) in a container, and copies
# its binary $(2) to $(3).
define install-rpm-pkg
	docker run --rm -v $(TOOLS_BIN):/out $(RPM_PKGS_IMAGE) sh -ec '\
		rpm --import $(RPM_PKGS_KEY); \
		zypper -q -n ar -f $(RPM_PKGS_REPO) pkgs; \
		zypper -q -n in -r pkgs --no-recommends $(1); \
		install -m 0755 -o $(shell id -u) -g $(shell id -g) $(2) /out/$(notdir $(3))'
endef

K3D = $(TOOLS_BIN)/k3d-$(K3D_VERSION)
$(K3D):
	rm -f $(TOOLS_BIN)/k3d*
ifeq ($(OS_NAME),linux)
	$(call install-rpm-pkg,k3d-$(K3D_VERSION:v%=%),/usr/bin/k3d,$(K3D))
else
	curl -sSfL -o $(K3D) "https://github.com/k3d-io/k3d/releases/download/$(K3D_VERSION)/k3d-$(OS_NAME)-$(OS_ARCH)"
	echo "$(K3D_SUM_$(OS_ARCH))  $(K3D)" | shasum -a 256 -c -
	chmod u+x $(K3D)
endif

GOLANGCI = $(TOOLS_BIN)/golangci-lint-$(GOLANGCI_VERSION)
GOLANGCI_VERSION_TRIMMED := $(GOLANGCI_VERSION:v%=%)
$(GOLANGCI):
	rm -rf $(TOOLS_BIN)/golangci*
ifeq ($(OS_NAME),linux)
	$(call install-rpm-pkg,golangci-lint-$(GOLANGCI_VERSION_TRIMMED),/usr/bin/golangci-lint,$(GOLANGCI))
else
	curl -sSfL -o $(TOOLS_BIN)/golangci.tar.gz \
		"https://github.com/golangci/golangci-lint/releases/download/$(GOLANGCI_VERSION)/golangci-lint-$(GOLANGCI_VERSION_TRIMMED)-$(OS_NAME)-$(OS_ARCH).tar.gz"
	echo "$(GOLANGCI_SUM_$(OS_ARCH))  $(TOOLS_BIN)/golangci.tar.gz" | shasum -a 256 -c -
	tar -xf $(TOOLS_BIN)/golangci.tar.gz -C $(TOOLS_BIN)
	mv $(TOOLS_BIN)/golangci-lint-$(GOLANGCI_VERSION_TRIMMED)-$(OS_NAME)-$(OS_ARCH)/golangci-lint $(GOLANGCI)
	chmod u+x $(GOLANGCI)
	rm -rf $(TOOLS_BIN)/golangci-lint-$(GOLANGCI_VERSION_TRIMMED)-$(OS_NAME)-$(OS_ARCH)
	rm -f $(TOOLS_BIN)/golangci.tar.gz
endif

KUBECTL = $(TOOLS_BIN)/kubectl-$(KUBECTL_VERSION)
# The RPM packages track the latest patch of each kubectl minor version.
KUBECTL_MINOR = $(shell echo $(KUBECTL_VERSION) | sed -E 's/^v([0-9]+\.[0-9]+).*/\1/')
$(KUBECTL):
	rm -f $(TOOLS_BIN)/kubectl*
ifeq ($(OS_NAME),linux)
	$(call install-rpm-pkg,kubectl-$(KUBECTL_MINOR),/usr/bin/kubectl-$(KUBECTL_MINOR),$(KUBECTL))
else
	curl -sSfL -o $(KUBECTL) \
		"https://dl.k8s.io/release/$(KUBECTL_VERSION)/bin/$(OS_NAME)/$(OS_ARCH)/kubectl"
	echo "$(KUBECTL_SUM_$(OS_ARCH))  $(KUBECTL)" | shasum -a 256 -c -
	chmod u+x $(KUBECTL)
endif

HELM = $(TOOLS_BIN)/helm-$(HELM_VERSION)
# The RPM packages track the latest release of each helm major version.
HELM_MAJOR = $(shell echo $(HELM_VERSION) | sed -E 's/^v([0-9]+).*/\1/')
$(HELM):
	rm -rf $(TOOLS_BIN)/helm*
ifeq ($(OS_NAME),linux)
	$(call install-rpm-pkg,helm$(HELM_MAJOR),/usr/bin/helm$(HELM_MAJOR),$(HELM))
else
	mkdir -p $(TOOLS_BIN)/tmp-helm
	curl -sSfL -o $(TOOLS_BIN)/helm.tar.gz \
		"https://get.helm.sh/helm-$(HELM_VERSION)-$(OS_NAME)-$(OS_ARCH).tar.gz"
	echo "$(HELM_SUM_$(OS_ARCH))  $(TOOLS_BIN)/helm.tar.gz" | shasum -a 256 -c -
	tar -xf $(TOOLS_BIN)/helm.tar.gz --strip-components 1 -C $(TOOLS_BIN)/tmp-helm
	mv $(TOOLS_BIN)/tmp-helm/helm $(HELM)
	chmod u+x $(HELM)
	rm -rf $(TOOLS_BIN)/helm.tar.gz $(TOOLS_BIN)/tmp-helm
endif
