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
	"crypto/sha256"
	"encoding/hex"
	stdjson "encoding/json"
	gerrors "errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	sandboxv1alpha1 "github.com/alibaba/OpenSandbox/sandbox-k8s/apis/sandbox/v1alpha1"
	"github.com/alibaba/OpenSandbox/sandbox-k8s/internal/controller/eviction"
	"github.com/alibaba/OpenSandbox/sandbox-k8s/internal/controller/recycle"
	"github.com/alibaba/OpenSandbox/sandbox-k8s/internal/utils"
	"github.com/alibaba/OpenSandbox/sandbox-k8s/internal/utils/expectations"
	"github.com/alibaba/OpenSandbox/sandbox-k8s/internal/utils/fieldindex"
)

const (
	defaultRetryTime = 5 * time.Second
)

const (
	LabelPoolName     = "sandbox.opensandbox.io/pool-name"
	LabelPoolRevision = "sandbox.opensandbox.io/pool-revision"
)

const (
	defaultSyncSandboxAllocConcurrency = 256
	envSyncSandboxAllocConcurrency     = "SYNC_SANDBOX_ALLOC_CONCURRENCY"

	defaultRecyclePodConcurrency = 64
	envRecyclePodConcurrency     = "RECYCLE_POD_CONCURRENCY"
)

var (
	PoolScaleExpectations       = expectations.NewScaleExpectations()
	syncSandboxAllocConcurrency int
	recyclePodConcurrency       int
)

func init() {
	syncSandboxAllocConcurrency = defaultSyncSandboxAllocConcurrency
	if val := os.Getenv(envSyncSandboxAllocConcurrency); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			syncSandboxAllocConcurrency = n
		}
	}
	recyclePodConcurrency = defaultRecyclePodConcurrency
	if val := os.Getenv(envRecyclePodConcurrency); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			recyclePodConcurrency = n
		}
	}
}

// PoolReconciler reconciles a Pool object
type PoolReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	Recorder   record.EventRecorder
	Allocator  Allocator
	RestConfig *rest.Config
}

// +kubebuilder:rbac:groups=sandbox.opensandbox.io,resources=pools,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=sandbox.opensandbox.io,resources=pools/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sandbox.opensandbox.io,resources=pools/finalizers,verbs=update
// +kubebuilder:rbac:groups=sandbox.opensandbox.io,resources=batchsandboxes,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=pods/exec,verbs=create
// +kubebuilder:rbac:groups=core,resources=pods/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core,resources=events,verbs=get;list;watch;create;update;patch;delete

func (r *PoolReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, retErr error) {
	log := logf.FromContext(ctx)
	start := time.Now()
	defer func() {
		log.Info("Reconcile finished", "duration", time.Since(start).String(), "requeueAfter", result.RequeueAfter.String(), "error", retErr)
	}()
	// Fetch the Pool instance
	pool := &sandboxv1alpha1.Pool{}
	if err := r.Get(ctx, req.NamespacedName, pool); err != nil {
		if errors.IsNotFound(err) {
			// A recreated pool may have the same namespace/name. Never clear its
			// name-keyed in-memory state from a stale delete reconcile.
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request
		log.Error(err, "Failed to get Pool")
		return ctrl.Result{}, err
	}
	if !pool.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(pool, FinalizerPoolCleanup) {
			return ctrl.Result{}, fmt.Errorf("pool deletion cannot safely proceed without cleanup finalizer")
		}
		return r.reconcileDeletingPool(ctx, pool)
	}
	if !controllerutil.ContainsFinalizer(pool, FinalizerPoolCleanup) {
		if err := utils.UpdateFinalizer(r.Client, pool, utils.AddFinalizerOpType, FinalizerPoolCleanup); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Millisecond * 100}, nil
	}

	// List every physically present pod. Pods with a deletion timestamp remain
	// owned resources until the API server removes them; they must consume
	// capacity, but must never be scheduled.
	podList := &corev1.PodList{}
	if err := r.List(ctx, podList, &client.ListOptions{
		Namespace:     pool.Namespace,
		FieldSelector: fields.SelectorFromSet(fields.Set{fieldindex.IndexNameForOwnerRefUID: string(pool.UID)}),
	}); err != nil {
		log.Error(err, "Failed to list pods")
		return reconcile.Result{}, err
	}
	physicalPods, schedulePods := partitionPoolPods(pool, podList.Items)

	// List all batch sandboxes ref to the pool
	batchSandboxList := &sandboxv1alpha1.BatchSandboxList{}
	if err := r.List(ctx, batchSandboxList, &client.ListOptions{
		Namespace:     pool.Namespace,
		FieldSelector: fields.SelectorFromSet(fields.Set{fieldindex.IndexNameForPoolRef: pool.Name}),
	}); err != nil {
		log.Error(err, "Failed to list batch sandboxes")
		return reconcile.Result{}, err
	}
	batchSandboxes := make([]*sandboxv1alpha1.BatchSandbox, 0, len(batchSandboxList.Items))
	for i := range batchSandboxList.Items {
		batchSandbox := &batchSandboxList.Items[i]
		if batchSandbox.Spec.Template != nil {
			continue
		}
		batchSandboxes = append(batchSandboxes, batchSandbox)
	}
	log.Info("Pool reconcile", "pool", pool.Name, "physicalPods", len(physicalPods), "schedulablePods", len(schedulePods), "batchSandboxes", len(batchSandboxes))
	return r.reconcilePool(ctx, pool, batchSandboxes, physicalPods, schedulePods)
}

// reconcileDeletingPool blocks Pool deletion until every durable allocation for
// this exact Pool UID is physically absent and has been removed from its
// BatchSandbox. This prevents a same-name replacement pool from inheriting
// stale allocations.
func (r *PoolReconciler) reconcileDeletingPool(ctx context.Context, pool *sandboxv1alpha1.Pool) (ctrl.Result, error) {
	PoolScaleExpectations.DeleteExpectations(poolExpectationKey(pool))

	batchSandboxList := &sandboxv1alpha1.BatchSandboxList{}
	if err := r.List(ctx, batchSandboxList, client.InNamespace(pool.Namespace)); err != nil {
		return ctrl.Result{}, err
	}
	ownedPodsAbsent, err := r.ensurePoolOwnedPodsAbsent(ctx, pool)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !ownedPodsAbsent {
		return ctrl.Result{RequeueAfter: defaultRetryTime}, nil
	}
	pending := false
	for i := range batchSandboxList.Items {
		sandbox := &batchSandboxList.Items[i]
		candidate := sandbox.Spec.PoolRef == pool.Name
		allocation, err := parseSandboxAllocation(sandbox)
		if err != nil {
			if candidate {
				return ctrl.Result{}, err
			}
			continue
		}
		if !candidate && allocation.PoolUID != string(pool.UID) {
			continue
		}
		if !allocationBelongsToPool(allocation, sandbox, pool) {
			continue
		}

		absent, err := r.ensureAllocatedPodsAbsent(ctx, pool, allocation.Pods)
		if err != nil {
			return ctrl.Result{}, err
		}
		if !absent {
			pending = true
			continue
		}
		if err := r.clearSandboxPoolAllocation(ctx, sandbox, pool); err != nil {
			return ctrl.Result{}, err
		}
	}
	if pending {
		return ctrl.Result{RequeueAfter: defaultRetryTime}, nil
	}

	if err := r.Allocator.ClearPoolAllocation(ctx, pool.Namespace, pool.Name); err != nil {
		return ctrl.Result{}, err
	}
	if err := utils.UpdateFinalizer(r.Client, pool, utils.RemoveFinalizerOpType, FinalizerPoolCleanup); err != nil && !errors.IsNotFound(err) {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// allocationBelongsToPool requires the durable UID when present. Legacy
// pods-only evidence is retained for the matching PoolRef so it can be safely
// backfilled or cleaned before a same-name replacement is admitted.
func allocationBelongsToPool(allocation SandboxAllocation, sandbox *sandboxv1alpha1.BatchSandbox, pool *sandboxv1alpha1.Pool) bool {
	if allocation.PoolUID != "" {
		return allocation.PoolUID == string(pool.UID)
	}
	return sandbox.Spec.PoolRef == pool.Name && (allocation.PoolRef == "" || allocation.PoolRef == pool.Name)
}

// ensurePoolOwnedPodsAbsent lists every physical Pod controlled by the exact
// Pool UID and drives each active one into deletion. Allocation coverage is
// insufficient because idle Pods are also owned resources of the Pool.
func (r *PoolReconciler) ensurePoolOwnedPodsAbsent(ctx context.Context, pool *sandboxv1alpha1.Pool) (bool, error) {
	podList := &corev1.PodList{}
	if err := r.List(ctx, podList, client.InNamespace(pool.Namespace)); err != nil {
		return false, err
	}
	absent := true
	for i := range podList.Items {
		pod := &podList.Items[i]
		if !podOwnedByPool(pod, pool.UID) {
			continue
		}
		absent = false
		if pod.DeletionTimestamp.IsZero() {
			if err := r.Delete(ctx, pod); err != nil && !errors.IsNotFound(err) {
				return false, err
			}
		}
	}
	return absent, nil
}

// ensureAllocatedPodsAbsent initiates deletion when needed and returns true
// only once every allocated pod is NotFound. A pod with a deletion timestamp
// is still physical and intentionally keeps cleanup pending.
func (r *PoolReconciler) ensureAllocatedPodsAbsent(ctx context.Context, pool *sandboxv1alpha1.Pool, podNames []string) (bool, error) {
	absent := true
	for _, podName := range podNames {
		pod := &corev1.Pod{}
		err := r.Get(ctx, types.NamespacedName{Namespace: pool.Namespace, Name: podName}, pod)
		if errors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return false, err
		}
		if !podOwnedByPool(pod, pool.UID) {
			// A same-name Pod owned by another controller is not this Pool's
			// physical resource. Treat the original allocation Pod as absent.
			continue
		}
		absent = false
		if pod.DeletionTimestamp.IsZero() {
			if err := r.Delete(ctx, pod); err != nil && !errors.IsNotFound(err) {
				return false, err
			}
		}
	}
	return absent, nil
}

func podOwnedByPool(pod *corev1.Pod, poolUID types.UID) bool {
	for _, owner := range pod.OwnerReferences {
		if owner.Controller != nil && *owner.Controller && owner.UID == poolUID {
			return true
		}
	}
	return false
}

func (r *PoolReconciler) clearSandboxPoolAllocation(ctx context.Context, sandbox *sandboxv1alpha1.BatchSandbox, pool *sandboxv1alpha1.Pool) error {
	latest := &sandboxv1alpha1.BatchSandbox{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(sandbox), latest); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}
	allocation, err := parseSandboxAllocation(latest)
	if err != nil {
		return err
	}
	if !allocationBelongsToPool(allocation, latest, pool) {
		return nil
	}
	annotations := latest.GetAnnotations()
	delete(annotations, AnnoAllocStatusKey)
	delete(annotations, AnnoAllocReleaseKey)
	delete(annotations, AnnoAllocReleasedKey)
	latest.SetAnnotations(annotations)
	controllerutil.RemoveFinalizer(latest, FinalizerPoolAllocation)
	return r.Update(ctx, latest)
}

func poolExpectationKey(pool *sandboxv1alpha1.Pool) string {
	return string(pool.UID)
}

// partitionPoolPods splits physically present owned pods from pods that may be
// scheduled. A terminating pod belongs only to the physical set until its
// delete event removes it from the API server.
func partitionPoolPods(pool *sandboxv1alpha1.Pool, podItems []corev1.Pod) ([]*corev1.Pod, []*corev1.Pod) {
	physicalPods := make([]*corev1.Pod, 0, len(podItems))
	schedulePods := make([]*corev1.Pod, 0, len(podItems))
	for i := range podItems {
		pod := &podItems[i]
		PoolScaleExpectations.ObserveScale(poolExpectationKey(pool), expectations.Create, pod.Name)
		physicalPods = append(physicalPods, pod)
		if pod.DeletionTimestamp.IsZero() {
			schedulePods = append(schedulePods, pod)
		}
	}
	return physicalPods, schedulePods
}

// reconcilePool contains the main reconciliation logic
func (r *PoolReconciler) reconcilePool(ctx context.Context, pool *sandboxv1alpha1.Pool, batchSandboxes []*sandboxv1alpha1.BatchSandbox, physicalPods, schedulablePods []*corev1.Pod) (ctrl.Result, error) {
	var result ctrl.Result
	if len(physicalPods) != len(schedulablePods) {
		// A terminating pod has no guaranteed follow-up event while its finalizers
		// are stuck. Poll as a fallback; pod delete events still wake us promptly.
		result.RequeueAfter = defaultRetryTime
	}

	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		// 1. Get latest Pool CR
		latestPool := &sandboxv1alpha1.Pool{}
		if err := r.Get(ctx, client.ObjectKeyFromObject(pool), latestPool); err != nil {
			return err
		}

		// 2. Handle pod eviction
		schedulePods, evictionErr := r.handleEviction(ctx, latestPool, schedulablePods)
		if schedulePods == nil {
			return evictionErr
		}

		// 3. Schedule sandbox (compute + persist + sync)
		schedResult, err := r.scheduleSandbox(ctx, latestPool, batchSandboxes, schedulePods, physicalPods)
		if err != nil {
			return err
		}
		// Requeue if there are pending sandboxes waiting for scheduling
		if schedResult.SupplyCnt > 0 && result.RequeueAfter == 0 {
			result.RequeueAfter = defaultRetryTime
		}

		// Best-effort compatibility migration for allocations written before PoolRef
		// was included in the alloc-status annotation. Do not let a patch failure
		// interrupt scheduling, releasing, or scaling.
		for _, sandbox := range batchSandboxes {
			if err := r.backfillLegacyPoolAllocation(ctx, latestPool, sandbox, physicalPods, schedResult.LatestAllocation); err != nil {
				logf.FromContext(ctx).Error(err, "Failed to backfill legacy pool allocation", "pool", latestPool.Name, "sandbox", sandbox.Name)
				if result.RequeueAfter == 0 || result.RequeueAfter > defaultRetryTime {
					result.RequeueAfter = defaultRetryTime
				}
			}
		}
		for _, sandbox := range batchSandboxes {
			if err := r.backfillPoolAllocationUID(ctx, latestPool, sandbox, physicalPods, schedResult.LatestAllocation); err != nil {
				logf.FromContext(ctx).Error(err, "Failed to backfill pool allocation identity", "pool", latestPool.Name, "sandbox", sandbox.Name)
				if result.RequeueAfter == 0 || result.RequeueAfter > defaultRetryTime {
					result.RequeueAfter = defaultRetryTime
				}
			}
		}

		// 4. Handle pool upgrade
		updateResult, err := r.updatePool(ctx, latestPool, schedulePods, schedResult.IdlePods, int32(len(physicalPods)-len(schedulablePods)))
		if err != nil {
			return err
		}

		// 5. Handle pool scale
		toDeletePods := append(updateResult.ToDeletePods, schedResult.ToDelete...)
		args := &scaleArgs{
			updateRevision: updateResult.UpdateRevision,
			pods:           schedulePods,
			totalPodCnt:    int32(len(physicalPods)),
			terminatingCnt: int32(len(physicalPods) - len(schedulablePods)),
			allocatedCnt:   int32(len(schedResult.LatestAllocation)),
			idlePods:       updateResult.IdlePods,
			toDeletePods:   toDeletePods,
			supplyCnt:      schedResult.SupplyCnt + updateResult.SupplyUpdateRevision,
		}

		if err := r.scalePool(ctx, latestPool, args); err != nil {
			return err
		}

		// 6. Update pool status
		if err := r.updatePoolStatus(ctx, updateResult.UpdateRevision, latestPool, physicalPods, schedulePods, schedResult.LatestAllocation); err != nil {
			return err
		}

		if evictionErr != nil {
			return evictionErr
		}

		return nil
	})

	return result, err
}

// backfillLegacyPoolAllocation adds PoolRef and Generation to a verified legacy
// allocation annotation. It intentionally leaves all newer or ambiguous records
// untouched.
func (r *PoolReconciler) backfillLegacyPoolAllocation(ctx context.Context, pool *sandboxv1alpha1.Pool, sandbox *sandboxv1alpha1.BatchSandbox, pods []*corev1.Pod, latestAllocation map[string]string) error {
	if sandbox.Spec.PoolRef == "" || sandbox.Spec.PoolRef != pool.Name ||
		!sandbox.DeletionTimestamp.IsZero() ||
		!controllerutil.ContainsFinalizer(sandbox, FinalizerPoolAllocation) {
		return nil
	}

	allocation, valid := parseLegacySandboxAllocation(sandbox)
	if !valid {
		return nil
	}

	releasePods, valid := validLegacyAllocationRelease(sandbox.GetAnnotations(), AnnoAllocReleaseKey)
	if !valid {
		return nil
	}
	releasedPods, valid := validLegacyAllocationRelease(sandbox.GetAnnotations(), AnnoAllocReleasedKey)
	if !valid {
		return nil
	}
	if allocationIntersects(allocation.Pods, releasePods) || allocationIntersects(allocation.Pods, releasedPods) {
		return nil
	}

	poolPods := make(map[string]struct{}, len(pods))
	for _, pod := range pods {
		if pod != nil && pod.DeletionTimestamp.IsZero() && pod.Labels[LabelPoolName] == pool.Name {
			poolPods[pod.Name] = struct{}{}
		}
	}
	for _, podName := range allocation.Pods {
		if _, ok := poolPods[podName]; !ok {
			return nil
		}
		if latestAllocation[podName] != sandbox.Name {
			return nil
		}
	}

	allocation.PoolRef = pool.Name
	allocation.Generation = sandbox.Generation
	allocation.PoolUID = string(pool.UID)
	rawAllocation, err := json.Marshal(allocation)
	if err != nil {
		return err
	}
	patchData, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]string{AnnoAllocStatusKey: string(rawAllocation)},
		},
	})
	if err != nil {
		return err
	}
	obj := &sandboxv1alpha1.BatchSandbox{}
	obj.Name = sandbox.Name
	obj.Namespace = sandbox.Namespace
	return r.Patch(ctx, obj, client.RawPatch(types.MergePatchType, patchData))
}

// backfillPoolAllocationUID adds immutable Pool UID evidence to allocations
// written before PoolUID was introduced. Physical ownership and current
// in-memory allocation must both agree before it changes durable state.
func (r *PoolReconciler) backfillPoolAllocationUID(ctx context.Context, pool *sandboxv1alpha1.Pool, sandbox *sandboxv1alpha1.BatchSandbox, pods []*corev1.Pod, latestAllocation map[string]string) error {
	if sandbox.Spec.PoolRef != pool.Name || !controllerutil.ContainsFinalizer(sandbox, FinalizerPoolAllocation) {
		return nil
	}
	allocation, err := parseSandboxAllocation(sandbox)
	if err != nil || allocation.PoolUID != "" || allocation.PoolRef != pool.Name {
		return err
	}
	poolPods := make(map[string]struct{}, len(pods))
	for _, pod := range pods {
		if pod != nil {
			poolPods[pod.Name] = struct{}{}
		}
	}
	for _, podName := range allocation.Pods {
		if _, ok := poolPods[podName]; !ok || latestAllocation[podName] != sandbox.Name {
			return nil
		}
	}
	allocation.PoolUID = string(pool.UID)
	rawAllocation, err := json.Marshal(allocation)
	if err != nil {
		return err
	}
	obj := &sandboxv1alpha1.BatchSandbox{ObjectMeta: metav1.ObjectMeta{Name: sandbox.Name, Namespace: sandbox.Namespace}}
	return r.Patch(ctx, obj, client.RawPatch(types.MergePatchType, []byte(fmt.Sprintf(`{"metadata":{"annotations":{"%s":%q}}}`, AnnoAllocStatusKey, string(rawAllocation)))))
}

// parseLegacySandboxAllocation accepts only the historical pods-only JSON
// shape. Explicit or partial newer evidence is never rewritten by migration.
func parseLegacySandboxAllocation(sandbox *sandboxv1alpha1.BatchSandbox) (SandboxAllocation, bool) {
	raw, ok := sandbox.GetAnnotations()[AnnoAllocStatusKey]
	if !ok {
		return SandboxAllocation{}, false
	}
	var payload map[string]stdjson.RawMessage
	if err := json.Unmarshal([]byte(raw), &payload); err != nil || payload == nil {
		return SandboxAllocation{}, false
	}
	if _, exists := payload["poolRef"]; exists {
		return SandboxAllocation{}, false
	}
	if _, exists := payload["generation"]; exists {
		return SandboxAllocation{}, false
	}
	if len(payload) != 1 {
		return SandboxAllocation{}, false
	}
	rawPods, ok := payload["pods"]
	if !ok {
		return SandboxAllocation{}, false
	}
	var pods []string
	if err := json.Unmarshal(rawPods, &pods); err != nil || !validLegacyAllocationPods(pods) {
		return SandboxAllocation{}, false
	}
	return SandboxAllocation{Pods: pods}, true
}

func validLegacyAllocationPods(pods []string) bool {
	if len(pods) == 0 {
		return false
	}
	return validUniqueDNS1123PodNames(pods)
}

// validLegacyAllocationRelease verifies that an optional release annotation has
// an explicit, non-null pods list whose pod names are valid and unique.
func validLegacyAllocationRelease(annotations map[string]string, key string) ([]string, bool) {
	raw, ok := annotations[key]
	if !ok {
		return nil, true
	}

	var payload map[string]stdjson.RawMessage
	if err := json.Unmarshal([]byte(raw), &payload); err != nil || payload == nil {
		return nil, false
	}
	rawPods, ok := payload["pods"]
	if !ok {
		return nil, false
	}
	var pods []string
	if err := json.Unmarshal(rawPods, &pods); err != nil || pods == nil || !validUniqueDNS1123PodNames(pods) {
		return nil, false
	}
	return pods, true
}

func validUniqueDNS1123PodNames(pods []string) bool {
	seen := make(map[string]struct{}, len(pods))
	for _, podName := range pods {
		if podName == "" || len(validation.IsDNS1123Subdomain(podName)) != 0 {
			return false
		}
		if _, ok := seen[podName]; ok {
			return false
		}
		seen[podName] = struct{}{}
	}
	return true
}

func allocationIntersects(allocationPods, otherPods []string) bool {
	allocationSet := make(map[string]struct{}, len(allocationPods))
	for _, podName := range allocationPods {
		allocationSet[podName] = struct{}{}
	}
	for _, podName := range otherPods {
		if _, ok := allocationSet[podName]; ok {
			return true
		}
	}
	return false
}

func (r *PoolReconciler) calculateRevision(pool *sandboxv1alpha1.Pool) (string, error) {
	template, err := json.Marshal(pool.Spec.Template)
	if err != nil {
		return "", err
	}
	revision := sha256.Sum256(template)
	return hex.EncodeToString(revision[:8]), nil
}

// SetupWithManager sets up the controller with the Manager.
// Todo pod deletion expectations

func (r *PoolReconciler) SetupWithManager(mgr ctrl.Manager, maxConcurrentReconciles int) error {
	poolPredicate := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldPool, okOld := e.ObjectOld.(*sandboxv1alpha1.Pool)
			newPool, okNew := e.ObjectNew.(*sandboxv1alpha1.Pool)
			if !okOld || !okNew {
				return false
			}
			return oldPool.Generation != newPool.Generation ||
				(oldPool.DeletionTimestamp.IsZero() && !newPool.DeletionTimestamp.IsZero())
		},
	}

	filterBatchSandbox := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			bsb, ok := e.Object.(*sandboxv1alpha1.BatchSandbox)
			return ok && bsb.Spec.PoolRef != ""
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldObj, okOld := e.ObjectOld.(*sandboxv1alpha1.BatchSandbox)
			newObj, okNew := e.ObjectNew.(*sandboxv1alpha1.BatchSandbox)
			if !okOld || !okNew || newObj.Spec.PoolRef == "" {
				return false
			}
			if oldObj.Annotations[AnnoAllocReleaseKey] != newObj.Annotations[AnnoAllocReleaseKey] || oldObj.Spec.Replicas != newObj.Spec.Replicas {
				return true
			}
			return oldObj.DeletionTimestamp.IsZero() && !newObj.DeletionTimestamp.IsZero()
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			bsb, ok := e.Object.(*sandboxv1alpha1.BatchSandbox)
			return ok && bsb.Spec.PoolRef != ""
		},
		GenericFunc: func(e event.GenericEvent) bool {
			bsb, ok := e.Object.(*sandboxv1alpha1.BatchSandbox)
			return ok && bsb.Spec.PoolRef != ""
		},
	}

	findPoolForBatchSandbox := func(ctx context.Context, obj client.Object) []reconcile.Request {
		log := logf.FromContext(ctx)
		batchSandbox, ok := obj.(*sandboxv1alpha1.BatchSandbox)
		if !ok {
			log.Error(nil, "Invalid object type, expected BatchSandbox")
			return nil
		}
		return []reconcile.Request{
			{
				NamespacedName: types.NamespacedName{
					Namespace: batchSandbox.Namespace,
					Name:      batchSandbox.Spec.PoolRef,
				},
			},
		}
	}

	filterBatchSandboxDetached := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldObj, okOld := e.ObjectOld.(*sandboxv1alpha1.BatchSandbox)
			newObj, okNew := e.ObjectNew.(*sandboxv1alpha1.BatchSandbox)
			if !okOld || !okNew {
				return false
			}
			return oldObj.Spec.PoolRef != "" && newObj.Spec.PoolRef == ""
		},
	}

	enqueueOldPoolForDetachedBatchSandbox := handler.Funcs{
		UpdateFunc: func(_ context.Context, e event.UpdateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			oldObj, ok := e.ObjectOld.(*sandboxv1alpha1.BatchSandbox)
			if !ok || oldObj.Spec.PoolRef == "" {
				return
			}
			q.Add(reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: oldObj.Namespace,
					Name:      oldObj.Spec.PoolRef,
				},
			})
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&sandboxv1alpha1.Pool{}, builder.WithPredicates(poolPredicate)).
		Owns(&corev1.Pod{}).
		Watches(
			&sandboxv1alpha1.BatchSandbox{},
			handler.EnqueueRequestsFromMapFunc(findPoolForBatchSandbox),
			builder.WithPredicates(filterBatchSandbox),
		).
		Watches(
			&sandboxv1alpha1.BatchSandbox{},
			enqueueOldPoolForDetachedBatchSandbox,
			builder.WithPredicates(filterBatchSandboxDetached),
		).
		Named("pool").
		WithOptions(controller.Options{MaxConcurrentReconciles: maxConcurrentReconciles}).
		Complete(r)
}

func (r *PoolReconciler) doAllocate(ctx context.Context, pool *sandboxv1alpha1.Pool, batchSandboxes []*sandboxv1alpha1.BatchSandbox, pods []*corev1.Pod, toAllocate map[string][]string) error {
	// 1. Compute latest allocated pods per sandbox (merge current + newly allocated).
	toSyncMap := r.getLatestAllocated(ctx, pool, batchSandboxes, toAllocate)

	// 2. Persist allocation and its immutable Pool UID evidence.
	if err := r.syncSandboxConcurrently(ctx, batchSandboxes, toSyncMap, r.Allocator.SyncSandboxAllocation, "allocated"); err != nil {
		return err
	}
	return r.persistPoolAllocationUIDs(ctx, pool, batchSandboxes, toSyncMap)
}

func (r *PoolReconciler) persistPoolAllocationUIDs(ctx context.Context, pool *sandboxv1alpha1.Pool, batchSandboxes []*sandboxv1alpha1.BatchSandbox, allocations map[string][]string) error {
	byName := make(map[string]*sandboxv1alpha1.BatchSandbox, len(batchSandboxes))
	for _, sandbox := range batchSandboxes {
		byName[sandbox.Name] = sandbox
	}
	for sandboxName := range allocations {
		sandbox := byName[sandboxName]
		if sandbox == nil {
			continue
		}
		allocation, err := parseSandboxAllocation(sandbox)
		if err != nil || allocation.PoolRef != pool.Name || allocation.PoolUID == string(pool.UID) {
			if err != nil {
				return err
			}
			continue
		}
		allocation.PoolUID = string(pool.UID)
		rawAllocation, err := json.Marshal(allocation)
		if err != nil {
			return err
		}
		annotations := sandbox.GetAnnotations()
		annotations[AnnoAllocStatusKey] = string(rawAllocation)
		sandbox.SetAnnotations(annotations)
		obj := &sandboxv1alpha1.BatchSandbox{ObjectMeta: metav1.ObjectMeta{Name: sandbox.Name, Namespace: sandbox.Namespace}}
		if err := r.Patch(ctx, obj, client.RawPatch(types.MergePatchType, []byte(fmt.Sprintf(`{"metadata":{"annotations":{"%s":%q}}}`, AnnoAllocStatusKey, string(rawAllocation))))); err != nil {
			return err
		}
	}
	return nil
}

// getLatestAllocated computes the latest allocated pods for each sandbox by merging current allocation with new pods to allocate.
func (r *PoolReconciler) getLatestAllocated(ctx context.Context, pool *sandboxv1alpha1.Pool, batchSandboxes []*sandboxv1alpha1.BatchSandbox, toAllocate map[string][]string) map[string][]string {
	log := logf.FromContext(ctx)
	sandboxByName := make(map[string]*sandboxv1alpha1.BatchSandbox, len(batchSandboxes))
	for _, bs := range batchSandboxes {
		sandboxByName[bs.Name] = bs
	}

	toSyncMap := make(map[string][]string, len(toAllocate))
	for sandboxName, allocPods := range toAllocate {
		if len(allocPods) == 0 {
			continue
		}
		sandbox, ok := sandboxByName[sandboxName]
		if !ok {
			log.Error(nil, "Sandbox not found for allocate", "sandbox", sandboxName)
			continue
		}
		currentAllocated, err := r.Allocator.GetSandboxAllocation(ctx, sandbox)
		if err != nil {
			log.Error(err, "Failed to get sandbox allocated", "sandbox", sandboxName)
			continue
		}
		toSyncMap[sandboxName] = append(currentAllocated, allocPods...)
	}
	return toSyncMap
}

// syncSandboxConcurrently syncs allocation or released state for each sandbox concurrently.
// Each sandbox is an independent resource, so concurrent writes are safe.
func (r *PoolReconciler) syncSandboxConcurrently(ctx context.Context, batchSandboxes []*sandboxv1alpha1.BatchSandbox, toSyncMap map[string][]string, syncFn func(context.Context, *sandboxv1alpha1.BatchSandbox, []string) error, label string) error {
	log := logf.FromContext(ctx)

	sandboxByName := make(map[string]*sandboxv1alpha1.BatchSandbox, len(batchSandboxes))
	for _, bs := range batchSandboxes {
		sandboxByName[bs.Name] = bs
	}

	errCh := make(chan error, len(toSyncMap))
	sem := make(chan struct{}, syncSandboxAllocConcurrency)
	var wg sync.WaitGroup
	for sandboxName, pods := range toSyncMap {
		sandbox, ok := sandboxByName[sandboxName]
		if !ok {
			log.Error(nil, "Sandbox not found for sync "+label, "sandbox", sandboxName)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := syncFn(ctx, sandbox, pods); err != nil {
				log.Error(err, "Failed to sync sandbox "+label, "sandbox", sandbox.Name)
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	var errs []error
	for err := range errCh {
		errs = append(errs, err)
	}
	return gerrors.Join(errs...)
}

func (r *PoolReconciler) doRecycle(ctx context.Context, pool *sandboxv1alpha1.Pool, batchSandboxes []*sandboxv1alpha1.BatchSandbox, pods []*corev1.Pod, toRecycle map[string][]string) (map[string][]string, []string, error) {
	if len(toRecycle) == 0 {
		return nil, nil, nil
	}

	handler, err := recycle.NewHandler(r.Client, r.RestConfig, pool)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get recycle handler for pool %s: %w", pool.Name, err)
	}

	results := r.runRecycleTasks(ctx, pool, pods, toRecycle, handler)
	return collectRecycleResults(ctx, results)
}

type recycleResult struct {
	sandboxName string
	podName     string
	status      *recycle.Status
	err         error
}

// runRecycleTasks executes TryRecycle concurrently for each (sandbox, pod) pair and
// returns one result per task.
func (r *PoolReconciler) runRecycleTasks(ctx context.Context, pool *sandboxv1alpha1.Pool, pods []*corev1.Pod, toRecycle map[string][]string, handler recycle.Handler) []recycleResult {
	podByName := make(map[string]*corev1.Pod, len(pods))
	for _, p := range pods {
		podByName[p.Name] = p
	}

	// Flatten the map into an ordered slice so goroutines can write by index.
	type task struct {
		sandboxName string
		podName     string
	}
	var tasks []task
	for sandboxName, podNames := range toRecycle {
		for _, podName := range podNames {
			tasks = append(tasks, task{sandboxName: sandboxName, podName: podName})
		}
	}

	// Results are written by index so each goroutine writes to a unique slot without synchronization.
	results := make([]recycleResult, len(tasks))
	sem := make(chan struct{}, recyclePodConcurrency)
	var wg sync.WaitGroup
	for idx, task := range tasks {
		localIdx, localTask := idx, task
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			status, err := handler.TryRecycle(ctx, pool, podByName[localTask.podName], &recycle.Spec{ID: localTask.sandboxName})
			results[localIdx] = recycleResult{sandboxName: localTask.sandboxName, podName: localTask.podName, status: status, err: err}
		}()
	}
	wg.Wait()
	return results
}

// collectRecycleResults aggregates per-task results into the succeed map and delete list.
func collectRecycleResults(ctx context.Context, results []recycleResult) (map[string][]string, []string, error) {
	log := logf.FromContext(ctx)
	succeedMap := make(map[string][]string)
	var toDeletePods []string
	var errs []error

	for _, res := range results {
		if res.err != nil {
			log.Error(res.err, "Failed to recycle pod", "pod", res.podName, "sandbox", res.sandboxName)
			errs = append(errs, res.err)
			continue
		}
		if res.status.State == recycle.StateSucceeded {
			succeedMap[res.sandboxName] = append(succeedMap[res.sandboxName], res.podName)
		}
		if res.status.NeedDelete {
			toDeletePods = append(toDeletePods, res.podName)
		}
	}
	return succeedMap, toDeletePods, gerrors.Join(errs...)
}

// doRelease runs the recycle operation for pods to be returned to the pool,
// then persists the released state to each sandbox's annotation.
func (r *PoolReconciler) doRelease(ctx context.Context, pool *sandboxv1alpha1.Pool, batchSandboxes []*sandboxv1alpha1.BatchSandbox, pods []*corev1.Pod, toRelease map[string][]string) ([]string, error) {
	log := logf.FromContext(ctx)

	// 1. Recycle pods.
	succeedMap, toDeletePods, err := r.doRecycle(ctx, pool, batchSandboxes, pods, toRelease)
	if err != nil {
		log.Error(err, "Some errors occurred during recycle")
		r.Recorder.Eventf(pool, corev1.EventTypeWarning, EventReasonFailedRecyclePod, "Failed to recycle some pods: %v", err)
	}

	// Emit recycle success events.
	var allRecycled []string
	for _, recycledPods := range succeedMap {
		allRecycled = append(allRecycled, recycledPods...)
	}
	if len(allRecycled) > 0 {
		r.Recorder.Eventf(pool, corev1.EventTypeNormal, EventReasonPodRecycled, "Recycled %d pod(s): %v", len(allRecycled), allRecycled)
	}

	// 2. Compute latest released pods per sandbox (merge current + recycle-succeeded).
	// Also collect orphan pods whose sandboxes no longer exist.
	toSyncMap, orphanPods := r.getLatestReleased(ctx, batchSandboxes, succeedMap)

	// 3. Concurrently sync each sandbox's Released annotation.
	syncErr := r.syncSandboxConcurrently(ctx, batchSandboxes, toSyncMap, r.Allocator.SyncSandboxReleased, "released")
	if syncErr != nil {
		log.Error(syncErr, "Failed to sync released")
	}

	// 4. Release in-memory allocations for orphan pods directly (no annotation to persist).
	if len(orphanPods) > 0 {
		r.Allocator.ReleasePodsAllocation(ctx, pool.Namespace, pool.Name, orphanPods)
	}

	return toDeletePods, gerrors.Join(err, syncErr)
}

// getLatestReleased computes the latest released pods for each sandbox by merging current released with recycle-succeeded pods.
// It also returns orphanPods: pods from succeedMap whose sandbox no longer exists and should be released directly by the caller.
func (r *PoolReconciler) getLatestReleased(ctx context.Context, batchSandboxes []*sandboxv1alpha1.BatchSandbox, succeedMap map[string][]string) (map[string][]string, []string) {
	log := logf.FromContext(ctx)
	sandboxByName := make(map[string]*sandboxv1alpha1.BatchSandbox, len(batchSandboxes))
	for _, bs := range batchSandboxes {
		sandboxByName[bs.Name] = bs
	}

	toSyncMap := make(map[string][]string, len(succeedMap))
	orphanPods := make([]string, 0)
	for sandboxName, succeedPods := range succeedMap {
		if len(succeedPods) == 0 {
			continue
		}
		sandbox, ok := sandboxByName[sandboxName]
		if !ok {
			// Orphan sandbox: deleted before recycle completed. Collect its pods for direct release.
			log.Info("GC: sandbox not found for recycle result, collecting orphan pods", "sandbox", sandboxName, "pods", succeedPods)
			orphanPods = append(orphanPods, succeedPods...)
			continue
		}
		currentReleased, err := r.Allocator.GetSandboxReleased(ctx, sandbox)
		if err != nil {
			log.Error(err, "Failed to get sandbox released", "sandbox", sandboxName)
			continue
		}
		toSyncMap[sandboxName] = append(currentReleased, succeedPods...)
	}
	return toSyncMap, orphanPods
}

func (r *PoolReconciler) scheduleSandbox(ctx context.Context, pool *sandboxv1alpha1.Pool, batchSandboxes []*sandboxv1alpha1.BatchSandbox, pods, physicalPods []*corev1.Pod) (*ScheduleResult, error) {
	log := logf.FromContext(ctx)
	// 1. Compute scheduling actions.
	spec := &AllocSpec{
		Sandboxes: batchSandboxes,
		Pool:      pool,
		Pods:      pods,
	}
	allocAction, err := r.Allocator.Schedule(ctx, spec)
	if err != nil {
		r.Recorder.Eventf(pool, corev1.EventTypeWarning, EventReasonAllocationFailed, "Failed to schedule sandboxes: %v", err)
		return nil, err
	}
	log.Info("Allocate action", "pool", pool.Name, "toAllocate", allocAction.ToAllocate, "toRelease", allocAction.ToRelease)

	// 2. Execute scheduling actions.
	// 2.1 Execute ToAllocate / update in-memory store.
	err = r.doAllocate(ctx, pool, batchSandboxes, pods, allocAction.ToAllocate)
	if err != nil {
		return nil, err
	}

	// Emit allocation events.
	sandboxByName := make(map[string]*sandboxv1alpha1.BatchSandbox, len(batchSandboxes))
	for _, bs := range batchSandboxes {
		sandboxByName[bs.Name] = bs
	}
	for sandboxName, allocPods := range allocAction.ToAllocate {
		if len(allocPods) == 0 {
			continue
		}
		r.Recorder.Eventf(pool, corev1.EventTypeNormal, EventReasonAllocationSucceeded,
			"Allocated %d pod(s) to sandbox %s: %v", len(allocPods), sandboxName, allocPods)
		if sbx, ok := sandboxByName[sandboxName]; ok {
			r.Recorder.Eventf(sbx, corev1.EventTypeNormal, EventReasonScheduled,
				"Successfully assigned %d pod(s) from pool %s: %v", len(allocPods), pool.Name, allocPods)
		}
	}

	// 2.2 Execute ToRelease / release in-memory store.
	toDeletePods, err := r.doRelease(ctx, pool, batchSandboxes, physicalPods, allocAction.ToRelease)
	if err != nil {
		return nil, err
	}

	// 3. Return schedule result
	latestAllocation, err := r.Allocator.GetPoolAllocation(ctx, pool)
	if err != nil {
		return nil, err
	}
	idlePods := make([]string, 0)
	for _, pod := range pods {
		if _, ok := latestAllocation[pod.Name]; !ok {
			idlePods = append(idlePods, pod.Name)
		}
	}
	result := &ScheduleResult{
		LatestAllocation: latestAllocation,
		IdlePods:         idlePods,
		ToDelete:         toDeletePods,
		SupplyCnt:        allocAction.PodSupplement,
	}

	log.Info("Schedule result", "pool", pool.Name, "toDeletePods", toDeletePods, "supplyCnt", allocAction.PodSupplement)
	return result, nil
}

func (r *PoolReconciler) updatePool(ctx context.Context, pool *sandboxv1alpha1.Pool, pods []*corev1.Pod, idlePods []string, terminatingCnt int32) (*UpdateResult, error) {
	updateRevision, err := r.calculateRevision(pool)
	if err != nil {
		return nil, err
	}
	strategy := NewPoolUpdateStrategy(pool)
	result := strategy.Compute(ctx, updateRevision, pods, idlePods)
	result.UpdateRevision = updateRevision
	limitUpdateForTerminationDebt(pool, result, int32(len(pods))+terminatingCnt, terminatingCnt)

	if len(result.ToDeletePods) > 0 {
		r.Recorder.Eventf(pool, corev1.EventTypeNormal, EventReasonPodUpdated,
			"Rolling update: deleting %d pod(s) for revision %s: %v", len(result.ToDeletePods), updateRevision, result.ToDeletePods)
	}

	return result, nil
}

// limitUpdateForTerminationDebt makes existing terminating pods consume the
// rolling-update unavailable budget. Deferred pods remain idle for normal
// scale accounting and are reconsidered after physical deletion completes.
func limitUpdateForTerminationDebt(pool *sandboxv1alpha1.Pool, result *UpdateResult, desiredTotal, terminatingCnt int32) {
	if terminatingCnt == 0 || len(result.ToDeletePods) == 0 {
		return
	}
	budget := max(getUpdateMaxUnavailable(pool, desiredTotal)-terminatingCnt, 0)
	if int32(len(result.ToDeletePods)) <= budget {
		return
	}
	deferred := result.ToDeletePods[budget:]
	result.IdlePods = append(result.IdlePods, deferred...)
	result.ToDeletePods = result.ToDeletePods[:budget]
	result.SupplyUpdateRevision = int32(len(result.ToDeletePods))
}

type scaleArgs struct {
	updateRevision string
	pods           []*corev1.Pod
	totalPodCnt    int32 // all physically present pods, including terminating ones
	terminatingCnt int32
	allocatedCnt   int32
	supplyCnt      int32 // to create
	idlePods       []string
	toDeletePods   []string
}

type ScheduleResult struct {
	// LatestAllocation is the most recent pod-to-sandbox allocation map.
	LatestAllocation map[string]string
	// IdlePods contains pods that are not currently allocated to any sandbox.
	IdlePods []string
	// ToDelete contains pods that the recycle handler has decided to delete
	// (e.g. direct deletion or restart failure fallback).
	ToDelete []string
	// SupplyCnt is the number of additional pods the allocator needs but are not yet available.
	SupplyCnt int32
}

type UpdateResult struct {
	UpdateRevision string
	IdlePods       []string
	ToDeletePods   []string
	// Supply Pods with update revision
	SupplyUpdateRevision int32
}

func (r *PoolReconciler) scalePool(ctx context.Context, pool *sandboxv1alpha1.Pool, args *scaleArgs) error {
	log := logf.FromContext(ctx)
	errs := make([]error, 0)
	pods := args.pods
	if satisfied, unsatisfiedDuration, dirtyPods := PoolScaleExpectations.SatisfiedExpectations(poolExpectationKey(pool)); !satisfied {
		if unsatisfiedDuration >= expectations.ExpectationTimeout {
			log.Info("Pool scale expectations timed out, clearing stale expectations",
				"unsatisfiedDuration", unsatisfiedDuration, "dirtyPods", dirtyPods)
			PoolScaleExpectations.DeleteExpectations(poolExpectationKey(pool))
		} else {
			log.Info("Pool scale is not ready, requeue", "unsatisfiedDuration", unsatisfiedDuration, "dirtyPods", dirtyPods)
			return fmt.Errorf("pool scale is not ready, %v", pool.Name)
		}
	}
	schedulableCnt := int32(len(args.pods))
	totalPodCnt := args.totalPodCnt
	allocatedCnt := args.allocatedCnt
	supplyCnt := args.supplyCnt
	toDeletePods := args.toDeletePods
	bufferCnt := schedulableCnt - allocatedCnt

	// Calculate desired buffer cnt.
	desiredBufferCnt := bufferCnt
	if bufferCnt < pool.Spec.CapacitySpec.BufferMin || bufferCnt > pool.Spec.CapacitySpec.BufferMax {
		desiredBufferCnt = (pool.Spec.CapacitySpec.BufferMin + pool.Spec.CapacitySpec.BufferMax) / 2
	}

	// Calculate desired schedulable cnt.
	desiredSchedulableCnt := max(allocatedCnt+supplyCnt+desiredBufferCnt, pool.Spec.CapacitySpec.PoolMin)
	desiredSchedulableCnt = min(desiredSchedulableCnt, pool.Spec.CapacitySpec.PoolMax)
	// A terminating pod is physical capacity debt. It is unavailable for
	// scheduling, but may borrow at most one existing maxUnavailable budget as
	// surge capacity. This bounds replacement when deletion is stuck while
	// retaining the established ScaleStrategy tuning convention.
	maxPhysicalPodCnt := r.maxPhysicalPods(pool, args.terminatingCnt)
	maxNewPods := max(maxPhysicalPodCnt-totalPodCnt, 0)

	log.Info("Scale pool decision", "pool", pool.Name,
		"totalPodCnt", totalPodCnt, "schedulableCnt", schedulableCnt,
		"terminatingCnt", args.terminatingCnt, "maxPhysicalPodCnt", maxPhysicalPodCnt,
		"allocatedCnt", allocatedCnt, "bufferCnt", bufferCnt,
		"desiredBufferCnt", desiredBufferCnt, "supplyCnt", supplyCnt,
		"desiredSchedulableCnt", desiredSchedulableCnt, "maxNewPods", maxNewPods,
		"toDeletePods", len(toDeletePods), "idlePods", len(args.idlePods))

	// Scale-up: create new pods if needed and allowed by the physical capacity bound.
	if desiredSchedulableCnt > schedulableCnt && maxNewPods > 0 {
		createCnt := min(desiredSchedulableCnt-schedulableCnt, maxNewPods)
		scaleMaxUnavailable := r.getScaleMaxUnavailable(pool, desiredSchedulableCnt)
		notReadyCnt := r.countNotReadyPods(pods)
		limitedCreateCnt := scaleMaxUnavailable - notReadyCnt
		createCnt = max(0, min(createCnt, limitedCreateCnt))
		if createCnt > 0 {
			log.Info("Scaling up pool with constraint", "pool", pool.Name,
				"createCnt", createCnt, "scaleMaxUnavailable", scaleMaxUnavailable,
				"notReadyCnt", notReadyCnt, "desiredSchedulableCnt", desiredSchedulableCnt, "limitedCreateCnt", limitedCreateCnt)
			for range createCnt {
				if err := r.createPoolPod(ctx, pool, args.updateRevision); err != nil {
					log.Error(err, "Failed to create pool pod")
					errs = append(errs, err)
				}
			}
		}
	}

	// Scale-down: delete redundant or excess pods
	scaleIn := int32(0)
	if desiredSchedulableCnt < schedulableCnt {
		scaleIn = schedulableCnt - desiredSchedulableCnt
	}
	if scaleIn > 0 || len(toDeletePods) > 0 {
		podsToDelete := r.pickPodsToDelete(pods, args.idlePods, args.toDeletePods, scaleIn)
		log.Info("Scaling down pool", "pool", pool.Name, "scaleIn", scaleIn, "toDeletePods", len(toDeletePods), "podsToDelete", len(podsToDelete))
		for _, pod := range podsToDelete {
			log.Info("Deleting pool pod", "pool", pool.Name, "pod", pod.Name)
			if err := r.Delete(ctx, pod); err != nil {
				log.Error(err, "Failed to delete pool pod", "pod", pod.Name)
				r.Recorder.Eventf(pool, corev1.EventTypeWarning, EventReasonFailedDelete, "Failed to delete pool pod %s: %v", pod.Name, err)
				errs = append(errs, err)
			} else {
				r.Recorder.Eventf(pool, corev1.EventTypeNormal, EventReasonSuccessfulDelete, "Deleted pool pod %s (scale-down)", pod.Name)
			}
		}
	}
	return gerrors.Join(errs...)
}

func (r *PoolReconciler) updatePoolStatus(ctx context.Context, updateRevision string, pool *sandboxv1alpha1.Pool, physicalPods, schedulePods []*corev1.Pod, podAllocation map[string]string) error {
	oldStatus := pool.Status.DeepCopy()
	availableCnt := int32(0)
	for _, pod := range schedulePods {
		if _, ok := podAllocation[pod.Name]; ok {
			continue
		}
		if !utils.IsPodReady(pod) {
			continue
		}
		availableCnt++
	}
	updatedCnt := int32(0)
	for _, pod := range physicalPods {
		if pod.Labels[LabelPoolRevision] == updateRevision {
			updatedCnt++
		}
	}
	terminatingCnt, oldestTerminatingAgeSeconds := terminatingPodStatus(physicalPods, time.Now())
	pool.Status.ObservedGeneration = pool.Generation
	pool.Status.Total = int32(len(physicalPods))
	pool.Status.Allocated = int32(len(podAllocation))
	pool.Status.Available = availableCnt
	pool.Status.Revision = updateRevision
	pool.Status.Updated = updatedCnt
	pool.Status.Terminating = terminatingCnt
	pool.Status.OldestTerminatingAgeSeconds = oldestTerminatingAgeSeconds
	pool.Status.Degraded = terminatingCnt > 0
	pool.Status.DegradedReason = ""
	if pool.Status.Degraded {
		pool.Status.DegradedReason = "TerminationDebt"
	}
	if equality.Semantic.DeepEqual(*oldStatus, pool.Status) {
		return nil
	}
	log := logf.FromContext(ctx)
	log.Info("Update pool status", "ObservedGeneration", pool.Status.ObservedGeneration, "Total", pool.Status.Total,
		"Allocated", pool.Status.Allocated, "Available", pool.Status.Available, "Revision", pool.Status.Revision,
		"Updated", pool.Status.Updated, "Terminating", pool.Status.Terminating,
		"OldestTerminatingAgeSeconds", pool.Status.OldestTerminatingAgeSeconds, "Degraded", pool.Status.Degraded)
	if err := r.Status().Update(ctx, pool); err != nil {
		return err
	}
	return nil
}

// terminatingPodStatus returns aggregate cleanup debt without exposing pod identity.
func terminatingPodStatus(pods []*corev1.Pod, now time.Time) (int32, int64) {
	var count int32
	var oldest time.Time
	for _, pod := range pods {
		if pod.DeletionTimestamp.IsZero() {
			continue
		}
		count++
		if oldest.IsZero() || pod.DeletionTimestamp.Time.Before(oldest) {
			oldest = pod.DeletionTimestamp.Time
		}
	}
	if oldest.IsZero() || now.Before(oldest) {
		return count, 0
	}
	return count, int64(now.Sub(oldest).Seconds())
}

func (r *PoolReconciler) pickPodsToDelete(pods []*corev1.Pod, idlePodNames []string, toDeletePodNames []string, scaleIn int32) []*corev1.Pod {
	podMap := make(map[string]*corev1.Pod, len(pods))
	for _, pod := range pods {
		podMap[pod.Name] = pod
	}

	podsToDelete := make([]*corev1.Pod, 0, len(toDeletePodNames)+int(scaleIn))
	selected := make(map[string]struct{}, len(toDeletePodNames)+int(scaleIn))
	appendIfActive := func(pod *corev1.Pod) bool {
		if pod == nil || !pod.DeletionTimestamp.IsZero() {
			return false
		}
		if _, exists := selected[pod.Name]; exists {
			return false
		}
		selected[pod.Name] = struct{}{}
		podsToDelete = append(podsToDelete, pod)
		return true
	}
	for _, name := range toDeletePodNames {
		appendIfActive(podMap[name])
	}

	idlePods := make([]*corev1.Pod, 0, len(idlePodNames))
	for _, name := range idlePodNames {
		if pod, ok := podMap[name]; ok {
			idlePods = append(idlePods, pod)
		}
	}
	sort.Slice(idlePods, func(i, j int) bool {
		return idlePods[i].CreationTimestamp.Before(&idlePods[j].CreationTimestamp)
	})
	for _, pod := range idlePods {
		if scaleIn <= 0 {
			break
		}
		if appendIfActive(pod) {
			scaleIn--
		}
	}
	return podsToDelete
}

// maxPhysicalPods allows a bounded replacement surge only while deletion debt
// exists. The surge uses the pool's existing ScaleStrategy.MaxUnavailable
// resolution, preserving one operational control for scale pacing and debt.
func (r *PoolReconciler) maxPhysicalPods(pool *sandboxv1alpha1.Pool, terminatingCnt int32) int32 {
	if terminatingCnt == 0 {
		return pool.Spec.CapacitySpec.PoolMax
	}
	return pool.Spec.CapacitySpec.PoolMax + r.getScaleMaxUnavailable(pool, max(pool.Spec.CapacitySpec.PoolMax, 1))
}

// getScaleMaxUnavailable returns the resolved maxUnavailable value.
// If not specified, defaults to 25% of desiredTotal.
// Minimum return value is 1 to ensure scaling progress.
func (r *PoolReconciler) getScaleMaxUnavailable(pool *sandboxv1alpha1.Pool, desiredTotal int32) int32 {
	defaultPercentage := intstr.FromString("25%")

	maxUnavailable := &defaultPercentage
	if pool.Spec.ScaleStrategy != nil && pool.Spec.ScaleStrategy.MaxUnavailable != nil {
		maxUnavailable = pool.Spec.ScaleStrategy.MaxUnavailable
	}

	result, err := intstr.GetScaledValueFromIntOrPercent(maxUnavailable, int(desiredTotal), true)
	if err != nil || result < 1 {
		result = 1
	}
	return int32(result)
}

// countNotReadyPods returns the count of pods that are not ready.
// A pod is considered not ready if it doesn't have a Ready condition
// with status True.
func (r *PoolReconciler) countNotReadyPods(pods []*corev1.Pod) int32 {
	var count int32
	for _, pod := range pods {
		if !utils.IsPodReady(pod) {
			count++
		}
	}
	return count
}

func (r *PoolReconciler) createPoolPod(ctx context.Context, pool *sandboxv1alpha1.Pool, updateRevision string) error {
	log := logf.FromContext(ctx)
	pod, err := utils.GetPodFromTemplate(pool.Spec.Template, pool, metav1.NewControllerRef(pool, sandboxv1alpha1.SchemeBuilder.GroupVersion.WithKind("Pool")))
	if err != nil {
		return err
	}
	pod.Namespace = pool.Namespace
	pod.Name = ""
	pod.GenerateName = pool.Name + "-"
	pod.Labels[LabelPoolName] = pool.Name
	pod.Labels[LabelPoolRevision] = updateRevision
	if err := ctrl.SetControllerReference(pool, pod, r.Scheme); err != nil {
		return err
	}
	if err := r.Create(ctx, pod); err != nil {
		r.Recorder.Eventf(pool, corev1.EventTypeWarning, EventReasonFailedCreate, "Failed to create pool pod: %v", err)
		return err
	}
	PoolScaleExpectations.ExpectScale(poolExpectationKey(pool), expectations.Create, pod.Name)
	log.Info("Created pool pod", "pool", pool.Name, "pod", pod.Name, "revision", updateRevision)
	r.Recorder.Eventf(pool, corev1.EventTypeNormal, EventReasonSuccessfulCreate, "Created pool pod: %v", pod.Name)
	return nil
}

// handleEviction fetches the current allocation, evicts idle pods marked for eviction,
// and returns the schedulable pods (excluding evicting idle pods) along with any eviction error.
// Eviction errors are non-fatal: they are returned to trigger a requeue but do not block the current reconcile.
func (r *PoolReconciler) handleEviction(ctx context.Context, pool *sandboxv1alpha1.Pool, pods []*corev1.Pod) ([]*corev1.Pod, error) {
	log := logf.FromContext(ctx)

	podAllocation, err := r.Allocator.GetPoolAllocation(ctx, pool)
	if err != nil {
		log.Error(err, "Failed to get pool allocation")
		return nil, err
	}

	handler := eviction.NewEvictionHandler(ctx, r.Client, pool)

	var evictionErrs []error
	filtered := make([]*corev1.Pod, 0, len(pods))
	for _, pod := range pods {
		if !handler.NeedsEviction(pod) {
			filtered = append(filtered, pod)
			continue
		}

		if sandboxName, allocated := podAllocation[pod.Name]; allocated {
			log.V(1).Info("Skipping eviction for allocated pod", "pod", pod.Name, "sandbox", sandboxName)
			filtered = append(filtered, pod)
			continue
		}

		// Idle pod marked for eviction: evict and exclude from scheduling
		log.Info("Evicting idle pool pod", "pool", pool.Name, "pod", pod.Name)
		if err := handler.Evict(ctx, pod); err != nil {
			log.Error(err, "Failed to evict pod", "pod", pod.Name)
			evictionErrs = append(evictionErrs, fmt.Errorf("failed to evict pod %s: %w", pod.Name, err))
		} else {
			r.Recorder.Eventf(pool, corev1.EventTypeNormal, EventReasonPodEvicted, "Evicted idle pod: %s", pod.Name)
		}
	}

	return filtered, gerrors.Join(evictionErrs...)
}
