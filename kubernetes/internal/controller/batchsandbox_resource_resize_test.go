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
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	sandboxv1alpha1 "github.com/alibaba/OpenSandbox/sandbox-k8s/apis/sandbox/v1alpha1"
)

func TestResizeBatchSandboxPodsPatchesSandboxContainer(t *testing.T) {
	desired := corev1.ResourceRequirements{
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("1"),
			corev1.ResourceMemory: resource.MustParse("1Gi"),
		},
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("500m"),
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "sandbox-0", Namespace: "default"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "sandbox",
			Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{
				corev1.ResourceCPU: resource.MustParse("500m"),
			}},
		}}},
	}
	batchSandbox := &sandboxv1alpha1.BatchSandbox{
		Spec: sandboxv1alpha1.BatchSandboxSpec{Template: &corev1.PodTemplateSpec{
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "sandbox", Resources: desired}}},
		}},
	}
	resizePatches := 0
	fakeClient := fake.NewClientBuilder().
		WithScheme(testscheme).
		WithObjects(pod).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(
				ctx context.Context,
				c client.Client,
				subResourceName string,
				obj client.Object,
				patch client.Patch,
				opts ...client.SubResourcePatchOption,
			) error {
				if subResourceName == "resize" {
					resizePatches++
				}
				return c.SubResource(subResourceName).Patch(ctx, obj, patch, opts...)
			},
		}).
		Build()
	reconciler := &BatchSandboxReconciler{Client: fakeClient}

	if err := reconciler.resizeBatchSandboxPods(context.Background(), batchSandbox, []*corev1.Pod{pod}); err != nil {
		t.Fatalf("resizeBatchSandboxPods() error = %v", err)
	}

	updated := &corev1.Pod{}
	if err := reconciler.Get(context.Background(), client.ObjectKeyFromObject(pod), updated); err != nil {
		t.Fatalf("get resized pod: %v", err)
	}
	if got := updated.Spec.Containers[0].Resources; !equality.Semantic.DeepEqual(got, desired) {
		t.Fatalf("sandbox resources = %#v, want %#v", got, desired)
	}
	if resizePatches != 1 {
		t.Fatalf("resize subresource patches = %d, want 1", resizePatches)
	}
}

func TestResizeBatchSandboxPodsSkipsMatchingResources(t *testing.T) {
	desired := corev1.ResourceRequirements{Limits: corev1.ResourceList{
		corev1.ResourceCPU: resource.MustParse("1"),
	}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "sandbox-0", Namespace: "default"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "sandbox", Resources: desired}}},
	}
	batchSandbox := &sandboxv1alpha1.BatchSandbox{
		Spec: sandboxv1alpha1.BatchSandboxSpec{Template: &corev1.PodTemplateSpec{
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "sandbox", Resources: desired}}},
		}},
	}
	reconciler := &BatchSandboxReconciler{
		Client: fake.NewClientBuilder().WithScheme(testscheme).WithObjects(pod).Build(),
	}

	if err := reconciler.resizeBatchSandboxPods(context.Background(), batchSandbox, []*corev1.Pod{pod}); err != nil {
		t.Fatalf("resizeBatchSandboxPods() error = %v", err)
	}
}
