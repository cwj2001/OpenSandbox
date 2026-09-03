// Copyright 2025 Alibaba Group Holding Ltd.
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
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sandboxv1alpha1 "github.com/alibaba/OpenSandbox/sandbox-k8s/apis/sandbox/v1alpha1"
)

func TestPoolPhysicalDeletionAccounting(t *testing.T) {
	now := time.Now()
	deletingAt := metav1.NewTime(now.Add(-2 * time.Minute))
	maxUnavailable := intstr.FromString("25%")
	pool := &sandboxv1alpha1.Pool{
		ObjectMeta: metav1.ObjectMeta{Name: "pool", Namespace: "default"},
		Spec: sandboxv1alpha1.PoolSpec{
			CapacitySpec:  sandboxv1alpha1.CapacitySpec{PoolMax: 8},
			ScaleStrategy: &sandboxv1alpha1.ScaleStrategy{MaxUnavailable: &maxUnavailable},
		},
	}
	active := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "active"}}
	terminating := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "terminating", DeletionTimestamp: &deletingAt}}

	physical, schedulable := partitionPoolPods(pool, []corev1.Pod{active, terminating})
	if len(physical) != 2 || len(schedulable) != 1 || schedulable[0].Name != "active" {
		t.Fatalf("partitionPoolPods() physical=%d schedulable=%v, want 2 and [active]", len(physical), schedulable)
	}

	if got := (&PoolReconciler{}).maxPhysicalPods(pool, 0); got != 8 {
		t.Fatalf("maxPhysicalPods() without debt = %d, want 8", got)
	}
	if got := (&PoolReconciler{}).maxPhysicalPods(pool, 1); got != 10 {
		t.Fatalf("maxPhysicalPods() with one terminating pod = %d, want bounded surge 10", got)
	}
	if got := (&PoolReconciler{}).maxPhysicalPods(pool, 100); got != 10 {
		t.Fatalf("maxPhysicalPods() with stuck terminating pods = %d, want bounded surge 10", got)
	}

	terminatingCnt, oldestAge := terminatingPodStatus(physical, now)
	if terminatingCnt != 1 || oldestAge != 120 {
		t.Fatalf("terminatingPodStatus() = (%d, %d), want (1, 120)", terminatingCnt, oldestAge)
	}

	selected := (&PoolReconciler{}).pickPodsToDelete(physical, []string{"active", "terminating"}, []string{"terminating"}, 2)
	if len(selected) != 1 || selected[0].Name != "active" {
		t.Fatalf("pickPodsToDelete() = %v, want only active pod", selected)
	}
}

func TestUpgradeTerminationDebtConsumesUnavailableBudget(t *testing.T) {
	maxUnavailable := intstr.FromString("25%")
	pool := &sandboxv1alpha1.Pool{Spec: sandboxv1alpha1.PoolSpec{
		UpdateStrategy: &sandboxv1alpha1.UpdateStrategy{MaxUnavailable: &maxUnavailable},
	}}
	result := &UpdateResult{
		IdlePods:             []string{},
		ToDeletePods:         []string{"old-1", "old-2"},
		SupplyUpdateRevision: 2,
	}

	limitUpdateForTerminationDebt(pool, result, 8, 2)
	if len(result.ToDeletePods) != 0 || result.SupplyUpdateRevision != 0 {
		t.Fatalf("termination debt must stop update deletion, got delete=%v supply=%d", result.ToDeletePods, result.SupplyUpdateRevision)
	}
	if len(result.IdlePods) != 2 {
		t.Fatalf("deferred update pods must remain idle for scale accounting, got %v", result.IdlePods)
	}
}

func TestPoolUIDSeparatesInMemoryAllocationState(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryAllocationStore()
	oldPool := &sandboxv1alpha1.Pool{ObjectMeta: metav1.ObjectMeta{Name: "pool", Namespace: "default", UID: "old-pool"}}
	newPool := &sandboxv1alpha1.Pool{ObjectMeta: metav1.ObjectMeta{Name: "pool", Namespace: "default", UID: "new-pool"}}
	if err := store.SetAllocation(ctx, oldPool, &PoolAllocation{PodAllocation: map[string]string{"old-pod": "sandbox"}}); err != nil {
		t.Fatal(err)
	}
	allocation, err := store.GetAllocation(ctx, newPool)
	if err != nil {
		t.Fatal(err)
	}
	if len(allocation.PodAllocation) != 0 {
		t.Fatalf("replacement pool inherited allocation: %v", allocation.PodAllocation)
	}
}

func TestLegacyPodsOnlyAllocationMatchesPoolReference(t *testing.T) {
	pool := &sandboxv1alpha1.Pool{ObjectMeta: metav1.ObjectMeta{Name: "pool", Namespace: "default", UID: "pool-uid"}}
	sandbox := &sandboxv1alpha1.BatchSandbox{Spec: sandboxv1alpha1.BatchSandboxSpec{PoolRef: "pool"}}
	if !allocationBelongsToPool(SandboxAllocation{Pods: []string{"pod"}}, sandbox, pool) {
		t.Fatal("pods-only legacy allocation was not selected for matching PoolRef")
	}
}

func TestForeignSameNamePodIsNotDeletedDuringPoolCleanup(t *testing.T) {
	ctx := context.Background()
	pool := &sandboxv1alpha1.Pool{ObjectMeta: metav1.ObjectMeta{Name: "pool", Namespace: "default", UID: "pool-uid"}}
	foreign := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "allocated-name", Namespace: "default"}}
	scheme := poolDeletionTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(foreign).Build()
	r := &PoolReconciler{Client: client, Scheme: scheme}
	absent, err := r.ensureAllocatedPodsAbsent(ctx, pool, []string{"allocated-name"})
	if err != nil || !absent {
		t.Fatalf("foreign same-name pod must be treated absent, got absent=%v err=%v", absent, err)
	}
	if err := client.Get(ctx, clientKey(foreign), &corev1.Pod{}); err != nil {
		t.Fatal("foreign pod was deleted")
	}
}

func TestDeleteReleaseWaitsForPhysicalAbsenceBeforeRemovingAllocationFinalizer(t *testing.T) {
	ctx := context.Background()
	now := metav1.NewTime(time.Now())
	allocation := `{"pods":["pool-pod"]}`
	sandbox := &sandboxv1alpha1.BatchSandbox{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "sandbox",
			Namespace:         "default",
			DeletionTimestamp: &now,
			Finalizers:        []string{FinalizerPoolAllocation},
			Annotations:       map[string]string{AnnoAllocStatusKey: allocation},
		},
		Spec: sandboxv1alpha1.BatchSandboxSpec{PoolRef: "pool"},
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := sandboxv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sandbox).Build()
	r := &PoolReconciler{
		Client:    client,
		Scheme:    scheme,
		Recorder:  record.NewFakeRecorder(10),
		Allocator: NewDefaultAllocator(client),
	}
	pool := &sandboxv1alpha1.Pool{ObjectMeta: metav1.ObjectMeta{Name: "pool", Namespace: "default"}}
	terminating := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pool-pod", Namespace: "default", DeletionTimestamp: &now}}
	release := map[string][]string{"sandbox": {"pool-pod"}}

	toDelete, err := r.doRelease(ctx, pool, []*sandboxv1alpha1.BatchSandbox{sandbox}, []*corev1.Pod{terminating}, release)
	if err != nil || len(toDelete) != 0 {
		t.Fatalf("doRelease() for terminating pod = (%v, %v), want no repeated delete and no error", toDelete, err)
	}
	stored := &sandboxv1alpha1.BatchSandbox{}
	if err := client.Get(ctx, clientKey(sandbox), stored); err != nil {
		t.Fatal(err)
	}
	if !containsFinalizer(stored.Finalizers, FinalizerPoolAllocation) {
		t.Fatal("allocation finalizer was removed before the pod was physically absent")
	}

	toDelete, err = r.doRelease(ctx, pool, []*sandboxv1alpha1.BatchSandbox{stored}, nil, release)
	if err != nil || len(toDelete) != 0 {
		t.Fatalf("doRelease() after pod absence = (%v, %v), want successful completion and no delete", toDelete, err)
	}
	if err := client.Get(ctx, clientKey(sandbox), stored); !apierrors.IsNotFound(err) {
		t.Fatalf("deleting sandbox remained after its allocation finalizer was removed: %v", err)
	}
}

func clientKey(object metav1.Object) client.ObjectKey {
	return client.ObjectKey{Namespace: object.GetNamespace(), Name: object.GetName()}
}

func containsFinalizer(finalizers []string, wanted string) bool {
	for _, finalizer := range finalizers {
		if finalizer == wanted {
			return true
		}
	}
	return false
}

func TestPoolDeletionWaitsForPhysicalAbsenceAndClearsDurableAllocation(t *testing.T) {
	ctx := context.Background()
	now := metav1.NewTime(time.Now())
	pool := &sandboxv1alpha1.Pool{ObjectMeta: metav1.ObjectMeta{
		Name:              "pool",
		Namespace:         "default",
		UID:               "old-pool",
		DeletionTimestamp: &now,
		Finalizers:        []string{FinalizerPoolCleanup},
	}}
	sandbox := &sandboxv1alpha1.BatchSandbox{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "sandbox",
			Namespace:   "default",
			Finalizers:  []string{FinalizerPoolAllocation},
			Annotations: map[string]string{AnnoAllocStatusKey: `{"pods":["pool-pod"],"poolRef":"pool","poolUID":"old-pool","generation":1}`},
		},
		Spec: sandboxv1alpha1.BatchSandboxSpec{PoolRef: "pool"},
	}
	controller := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name:              "pool-pod",
		Namespace:         "default",
		DeletionTimestamp: &now,
		Finalizers:        []string{"hold"},
		OwnerReferences:   []metav1.OwnerReference{{UID: pool.UID, Controller: &controller}},
	}}
	scheme := poolDeletionTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pool, sandbox, pod).Build()
	r := &PoolReconciler{Client: client, Scheme: scheme, Recorder: record.NewFakeRecorder(10), Allocator: NewDefaultAllocator(client)}

	result, err := r.reconcileDeletingPool(ctx, pool)
	if err != nil || result.RequeueAfter != defaultRetryTime {
		t.Fatalf("reconcileDeletingPool() while pod terminates = (%v, %v), want requeue", result, err)
	}
	storedSandbox := &sandboxv1alpha1.BatchSandbox{}
	if err := client.Get(ctx, clientKey(sandbox), storedSandbox); err != nil {
		t.Fatal(err)
	}
	if storedSandbox.Annotations[AnnoAllocStatusKey] == "" || !containsFinalizer(storedSandbox.Finalizers, FinalizerPoolAllocation) {
		t.Fatal("durable allocation was cleared before its pod was physically absent")
	}

	storedPool := &sandboxv1alpha1.Pool{}
	if err := client.Get(ctx, clientKey(pool), storedPool); err != nil {
		t.Fatal(err)
	}
	completedClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(storedPool, storedSandbox).Build()
	completed := &PoolReconciler{Client: completedClient, Scheme: scheme, Recorder: record.NewFakeRecorder(10), Allocator: NewDefaultAllocator(completedClient)}
	if _, err := completed.reconcileDeletingPool(ctx, storedPool); err != nil {
		t.Fatal(err)
	}
	if err := completedClient.Get(ctx, clientKey(sandbox), storedSandbox); err != nil {
		t.Fatal(err)
	}
	if _, exists := storedSandbox.Annotations[AnnoAllocStatusKey]; exists || containsFinalizer(storedSandbox.Finalizers, FinalizerPoolAllocation) {
		t.Fatal("durable allocation was not cleared after its pod became NotFound")
	}
	if err := completedClient.Get(ctx, clientKey(pool), storedPool); err == nil {
		if containsFinalizer(storedPool.Finalizers, FinalizerPoolCleanup) {
			t.Fatal("pool cleanup finalizer was retained after durable cleanup completed")
		}
	} else if !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
}

func TestPoolDeletionDoesNotClaimReplacementPoolAllocation(t *testing.T) {
	ctx := context.Background()
	now := metav1.NewTime(time.Now())
	pool := &sandboxv1alpha1.Pool{ObjectMeta: metav1.ObjectMeta{
		Name:              "pool",
		Namespace:         "default",
		UID:               "old-pool",
		DeletionTimestamp: &now,
		Finalizers:        []string{FinalizerPoolCleanup},
	}}
	sandbox := &sandboxv1alpha1.BatchSandbox{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "sandbox",
			Namespace:   "default",
			Finalizers:  []string{FinalizerPoolAllocation},
			Annotations: map[string]string{AnnoAllocStatusKey: `{"pods":["replacement-pod"],"poolRef":"pool","poolUID":"new-pool","generation":1}`},
		},
		Spec: sandboxv1alpha1.BatchSandboxSpec{PoolRef: "pool"},
	}
	scheme := poolDeletionTestScheme(t)
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pool, sandbox).Build()
	r := &PoolReconciler{Client: client, Scheme: scheme, Recorder: record.NewFakeRecorder(10), Allocator: NewDefaultAllocator(client)}
	if _, err := r.reconcileDeletingPool(ctx, pool); err != nil {
		t.Fatal(err)
	}
	storedSandbox := &sandboxv1alpha1.BatchSandbox{}
	if err := client.Get(ctx, clientKey(sandbox), storedSandbox); err != nil {
		t.Fatal(err)
	}
	if storedSandbox.Annotations[AnnoAllocStatusKey] == "" || !containsFinalizer(storedSandbox.Finalizers, FinalizerPoolAllocation) {
		t.Fatal("old pool deletion modified replacement pool allocation evidence")
	}
}

func poolDeletionTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := sandboxv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}
