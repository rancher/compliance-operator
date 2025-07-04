//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright 2025 SUSE LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by main. DO NOT EDIT.

package v1

import (
	genericcondition "github.com/rancher/wrangler/v3/pkg/genericcondition"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterScan) DeepCopyInto(out *ClusterScan) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterScan.
func (in *ClusterScan) DeepCopy() *ClusterScan {
	if in == nil {
		return nil
	}
	out := new(ClusterScan)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ClusterScan) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterScanAlertRule) DeepCopyInto(out *ClusterScanAlertRule) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterScanAlertRule.
func (in *ClusterScanAlertRule) DeepCopy() *ClusterScanAlertRule {
	if in == nil {
		return nil
	}
	out := new(ClusterScanAlertRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterScanBenchmark) DeepCopyInto(out *ClusterScanBenchmark) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterScanBenchmark.
func (in *ClusterScanBenchmark) DeepCopy() *ClusterScanBenchmark {
	if in == nil {
		return nil
	}
	out := new(ClusterScanBenchmark)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ClusterScanBenchmark) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterScanBenchmarkList) DeepCopyInto(out *ClusterScanBenchmarkList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ClusterScanBenchmark, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterScanBenchmarkList.
func (in *ClusterScanBenchmarkList) DeepCopy() *ClusterScanBenchmarkList {
	if in == nil {
		return nil
	}
	out := new(ClusterScanBenchmarkList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ClusterScanBenchmarkList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterScanBenchmarkSpec) DeepCopyInto(out *ClusterScanBenchmarkSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterScanBenchmarkSpec.
func (in *ClusterScanBenchmarkSpec) DeepCopy() *ClusterScanBenchmarkSpec {
	if in == nil {
		return nil
	}
	out := new(ClusterScanBenchmarkSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterScanList) DeepCopyInto(out *ClusterScanList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ClusterScan, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterScanList.
func (in *ClusterScanList) DeepCopy() *ClusterScanList {
	if in == nil {
		return nil
	}
	out := new(ClusterScanList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ClusterScanList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterScanProfile) DeepCopyInto(out *ClusterScanProfile) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterScanProfile.
func (in *ClusterScanProfile) DeepCopy() *ClusterScanProfile {
	if in == nil {
		return nil
	}
	out := new(ClusterScanProfile)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ClusterScanProfile) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterScanProfileList) DeepCopyInto(out *ClusterScanProfileList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ClusterScanProfile, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterScanProfileList.
func (in *ClusterScanProfileList) DeepCopy() *ClusterScanProfileList {
	if in == nil {
		return nil
	}
	out := new(ClusterScanProfileList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ClusterScanProfileList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterScanProfileSpec) DeepCopyInto(out *ClusterScanProfileSpec) {
	*out = *in
	if in.SkipTests != nil {
		in, out := &in.SkipTests, &out.SkipTests
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterScanProfileSpec.
func (in *ClusterScanProfileSpec) DeepCopy() *ClusterScanProfileSpec {
	if in == nil {
		return nil
	}
	out := new(ClusterScanProfileSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterScanReport) DeepCopyInto(out *ClusterScanReport) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterScanReport.
func (in *ClusterScanReport) DeepCopy() *ClusterScanReport {
	if in == nil {
		return nil
	}
	out := new(ClusterScanReport)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ClusterScanReport) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterScanReportList) DeepCopyInto(out *ClusterScanReportList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ClusterScanReport, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterScanReportList.
func (in *ClusterScanReportList) DeepCopy() *ClusterScanReportList {
	if in == nil {
		return nil
	}
	out := new(ClusterScanReportList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ClusterScanReportList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterScanReportSpec) DeepCopyInto(out *ClusterScanReportSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterScanReportSpec.
func (in *ClusterScanReportSpec) DeepCopy() *ClusterScanReportSpec {
	if in == nil {
		return nil
	}
	out := new(ClusterScanReportSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterScanSpec) DeepCopyInto(out *ClusterScanSpec) {
	*out = *in
	if in.ScheduledScanConfig != nil {
		in, out := &in.ScheduledScanConfig, &out.ScheduledScanConfig
		*out = new(ScheduledScanConfig)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterScanSpec.
func (in *ClusterScanSpec) DeepCopy() *ClusterScanSpec {
	if in == nil {
		return nil
	}
	out := new(ClusterScanSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterScanStatus) DeepCopyInto(out *ClusterScanStatus) {
	*out = *in
	if in.Display != nil {
		in, out := &in.Display, &out.Display
		*out = new(ClusterScanStatusDisplay)
		**out = **in
	}
	if in.Summary != nil {
		in, out := &in.Summary, &out.Summary
		*out = new(ClusterScanSummary)
		**out = **in
	}
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]genericcondition.GenericCondition, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterScanStatus.
func (in *ClusterScanStatus) DeepCopy() *ClusterScanStatus {
	if in == nil {
		return nil
	}
	out := new(ClusterScanStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterScanStatusDisplay) DeepCopyInto(out *ClusterScanStatusDisplay) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterScanStatusDisplay.
func (in *ClusterScanStatusDisplay) DeepCopy() *ClusterScanStatusDisplay {
	if in == nil {
		return nil
	}
	out := new(ClusterScanStatusDisplay)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterScanSummary) DeepCopyInto(out *ClusterScanSummary) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterScanSummary.
func (in *ClusterScanSummary) DeepCopy() *ClusterScanSummary {
	if in == nil {
		return nil
	}
	out := new(ClusterScanSummary)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ScanImageConfig) DeepCopyInto(out *ScanImageConfig) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ScanImageConfig.
func (in *ScanImageConfig) DeepCopy() *ScanImageConfig {
	if in == nil {
		return nil
	}
	out := new(ScanImageConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ScheduledScanConfig) DeepCopyInto(out *ScheduledScanConfig) {
	*out = *in
	if in.ScanAlertRule != nil {
		in, out := &in.ScanAlertRule, &out.ScanAlertRule
		*out = new(ClusterScanAlertRule)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ScheduledScanConfig.
func (in *ScheduledScanConfig) DeepCopy() *ScheduledScanConfig {
	if in == nil {
		return nil
	}
	out := new(ScheduledScanConfig)
	in.DeepCopyInto(out)
	return out
}
