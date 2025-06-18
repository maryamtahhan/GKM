/*
Copyright 2025.

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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CacheStatus defines the status of an individual kernel cache on a node
type CacheStatus struct {
	KernelCacheRef string             `json:"kernelCacheRef"`
	GpuType        string             `json:"gpuType"`
	DriverVersion  string             `json:"driverVersion"`
	Conditions     []metav1.Condition `json:"conditions,omitempty"`
	LastUpdated    metav1.Time        `json:"lastUpdated,omitempty"`
}

// TKMCacheNodeStatusSpec defines the desired state of TKMCacheNodeStatus
type TKMNodeStatusSpec struct {
	NodeName      string        `json:"nodeName"`
	CacheStatuses []CacheStatus `json:"cacheStatuses,omitempty"`
}

// TKMCacheNodeStatusStatus defines the observed state of TKMCacheNodeStatus
type TKMNodeStatusStatus struct {
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// TKMCacheNodeStatus is the Schema for the tkmnodestatuses API
type TKMNodeStatus struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TKMNodeStatusSpec   `json:"spec,omitempty"`
	Status TKMNodeStatusStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TKMNodeStatusList contains a list of TKMCacheNodeStatus
type TKMNodeStatusList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TKMNodeStatus `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TKMNodeStatus{}, &TKMNodeStatusList{})
}
