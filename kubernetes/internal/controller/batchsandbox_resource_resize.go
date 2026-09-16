// Copyright 2026 Alibaba Group Holding Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sandboxv1alpha1 "github.com/alibaba/OpenSandbox/sandbox-k8s/apis/sandbox/v1alpha1"
)

const sandboxContainerName = "sandbox"

// resizeBatchSandboxPods applies the template's main-container resources through
// Pod's resize subresource. It deliberately never mutates pooled Pods: their
// resource profile belongs to the Pool, not to an individual BatchSandbox.
func (r *BatchSandboxReconciler) resizeBatchSandboxPods(
	ctx context.Context,
	batchSandbox *sandboxv1alpha1.BatchSandbox,
	pods []*corev1.Pod,
) error {
	if batchSandbox.Spec.Template == nil {
		return nil
	}
	desired, found := resourcesForSandboxContainer(batchSandbox.Spec.Template.Spec.Containers)
	if !found {
		return nil
	}

	for _, pod := range pods {
		if pod.DeletionTimestamp != nil {
			continue
		}
		index := sandboxContainerIndex(pod.Spec.Containers)
		if index == -1 {
			return fmt.Errorf("pod %s does not contain %q", pod.Name, sandboxContainerName)
		}
		if equality.Semantic.DeepEqual(pod.Spec.Containers[index].Resources, desired) {
			continue
		}

		before := pod.DeepCopy()
		pod.Spec.Containers[index].Resources = *desired.DeepCopy()
		if err := r.SubResource("resize").Patch(ctx, pod, client.MergeFrom(before)); err != nil {
			return fmt.Errorf("resize pod %s: %w", pod.Name, err)
		}
	}
	return nil
}

func resourcesForSandboxContainer(containers []corev1.Container) (corev1.ResourceRequirements, bool) {
	index := sandboxContainerIndex(containers)
	if index == -1 {
		return corev1.ResourceRequirements{}, false
	}
	return containers[index].Resources, true
}

func sandboxContainerIndex(containers []corev1.Container) int {
	for index := range containers {
		if containers[index].Name == sandboxContainerName {
			return index
		}
	}
	return -1
}
