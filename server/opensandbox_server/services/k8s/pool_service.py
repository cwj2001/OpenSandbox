# Copyright 2025 Alibaba Group Holding Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Kubernetes Pool service for pre-warmed sandbox resource pools."""

import logging
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, status
from kubernetes.client import ApiException

from opensandbox_server.api.schema import (
    CreatePoolRequest,
    ListPoolsResponse,
    PoolCapacitySpec,
    PoolMemberContainerStatus,
    PoolMemberEvent,
    PoolMemberResponse,
    PoolMembersResponse,
    PoolResponse,
    PoolStatus,
    UpdatePoolRequest,
)
from opensandbox_server.services.constants import SandboxErrorCodes
from opensandbox_server.services.k8s.client import (
    K8sClient,
    OPENSANDBOX_API_GROUP,
    OPENSANDBOX_API_VERSION,
    POOL_KIND,
    POOL_PLURAL,
)
from opensandbox_server.tenants.context import get_current_tenant

logger = logging.getLogger(__name__)

_POOL_NAME_LABEL = "sandbox.opensandbox.io/pool-name"


class PoolService:
    """Service for managing Pool CRD resources in Kubernetes."""

    def __init__(self, k8s_client: K8sClient, namespace: str) -> None:
        """Initialize PoolService."""
        self._custom_api = k8s_client.get_custom_objects_api()
        self._k8s_client = k8s_client
        self._namespace = namespace

    def _resolve_namespace(self) -> str:
        tenant = get_current_tenant()
        return tenant.namespace if tenant else self._namespace

    def _build_pool_manifest(
        self,
        name: str,
        namespace: str,
        template: Dict[str, Any],
        capacity_spec: PoolCapacitySpec,
    ) -> Dict[str, Any]:
        """Build a Pool CRD manifest dict."""
        return {
            "apiVersion": f"{OPENSANDBOX_API_GROUP}/{OPENSANDBOX_API_VERSION}",
            "kind": POOL_KIND,
            "metadata": {
                "name": name,
                "namespace": namespace,
            },
            "spec": {
                "template": template,
                "capacitySpec": {
                    "bufferMax": capacity_spec.buffer_max,
                    "bufferMin": capacity_spec.buffer_min,
                    "poolMax": capacity_spec.pool_max,
                    "poolMin": capacity_spec.pool_min,
                },
            },
        }

    def _pool_from_raw(self, raw: Dict[str, Any]) -> PoolResponse:
        """Convert a raw Pool CRD dict to a PoolResponse model."""
        metadata = raw.get("metadata", {})
        spec = raw.get("spec", {})
        raw_status = raw.get("status")

        capacity = spec.get("capacitySpec", {})
        capacity_spec = PoolCapacitySpec(
            bufferMax=capacity.get("bufferMax", 0),
            bufferMin=capacity.get("bufferMin", 0),
            poolMax=capacity.get("poolMax", 0),
            poolMin=capacity.get("poolMin", 0),
        )

        pool_status: Optional[PoolStatus] = None
        if raw_status:
            pool_status = PoolStatus(
                total=raw_status.get("total", 0),
                allocated=raw_status.get("allocated", 0),
                available=raw_status.get("available", 0),
                revision=raw_status.get("revision", ""),
            )

        return PoolResponse(
            name=metadata.get("name", ""),
            capacitySpec=capacity_spec,
            status=pool_status,
            createdAt=metadata.get("creationTimestamp"),
        )

    def create_pool(self, request: CreatePoolRequest) -> PoolResponse:
        """Create a new Pool resource."""
        manifest = self._build_pool_manifest(
            name=request.name,
            namespace=self._namespace,
            template=request.template,
            capacity_spec=request.capacity_spec,
        )

        try:
            created = self._custom_api.create_namespaced_custom_object(
                group=OPENSANDBOX_API_GROUP,
                version=OPENSANDBOX_API_VERSION,
                namespace=self._namespace,
                plural=POOL_PLURAL,
                body=manifest,
            )
            logger.info(f"Created pool: name={request.name}, namespace={self._namespace}")
            return self._pool_from_raw(created)

        except ApiException as e:
            if e.status == 409:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={
                        "code": SandboxErrorCodes.K8S_POOL_ALREADY_EXISTS,
                        "message": f"Pool '{request.name}' already exists.",
                    },
                ) from e
            logger.error(f"Kubernetes API error creating pool {request.name}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "code": SandboxErrorCodes.K8S_POOL_API_ERROR,
                    "message": f"Failed to create pool: {e.reason}",
                },
            ) from e
        except Exception as e:
            logger.error(f"Unexpected error creating pool {request.name}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "code": SandboxErrorCodes.K8S_POOL_API_ERROR,
                    "message": f"Failed to create pool: {e}",
                },
            ) from e

    def _get_pool_raw(self, pool_name: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        try:
            return self._custom_api.get_namespaced_custom_object(
                group=OPENSANDBOX_API_GROUP,
                version=OPENSANDBOX_API_VERSION,
                namespace=namespace or self._namespace,
                plural=POOL_PLURAL,
                name=pool_name,
            )
        except ApiException as e:
            if e.status == 404:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail={
                        "code": SandboxErrorCodes.K8S_POOL_NOT_FOUND,
                        "message": f"Pool '{pool_name}' not found.",
                    },
                ) from e
            logger.error("Kubernetes API error getting Pool %s", pool_name)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "code": SandboxErrorCodes.K8S_POOL_API_ERROR,
                    "message": "Failed to get Pool.",
                },
            ) from e
        except Exception as e:
            logger.error("Unexpected error getting Pool %s", pool_name)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "code": SandboxErrorCodes.K8S_POOL_API_ERROR,
                    "message": "Failed to get Pool.",
                },
            ) from e

    def get_pool(self, pool_name: str) -> PoolResponse:
        """Retrieve a Pool by name."""
        return self._pool_from_raw(self._get_pool_raw(pool_name))

    def get_pool_members(self, pool_name: str, limit: int) -> PoolMembersResponse:
        """Return bounded diagnostics for Pods controller-owned by a Pool."""
        namespace = self._resolve_namespace()
        pool = self._get_pool_raw(pool_name, namespace)
        pool_uid = str((pool.get("metadata") or {}).get("uid") or "")
        if not pool_uid:
            logger.error("Pool %s is missing metadata.uid", pool_name)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "code": SandboxErrorCodes.K8S_POOL_API_ERROR,
                    "message": "Pool identity is unavailable.",
                },
            )
        try:
            pods = self._k8s_client.list_pods(
                namespace=namespace,
                label_selector=f"{_POOL_NAME_LABEL}={pool_name}",
                limit=limit + 1,
            )
        except Exception as e:
            logger.error("Failed to list Pool member Pods for %s", pool_name)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "code": SandboxErrorCodes.K8S_POOL_API_ERROR,
                    "message": "Failed to list Pool members.",
                },
            ) from e
        members = [pod for pod in pods if self._is_owner_verified_member(pod, pool_name, pool_uid)]
        members.sort(key=lambda pod: str(getattr(getattr(pod, "metadata", None), "name", "")))
        reported_count = (pool.get("status") or {}).get("total")
        member_count = (
            max(len(members), reported_count) if isinstance(reported_count, int) else len(members)
        )
        return PoolMembersResponse(
            poolName=pool_name,
            memberCount=member_count,
            truncated=len(pods) > limit or member_count > len(members),
            members=[self._member_from_pod(pod, namespace) for pod in members[:limit]],
        )

    @staticmethod
    def _is_owner_verified_member(pod: Any, pool_name: str, pool_uid: str) -> bool:
        metadata = getattr(pod, "metadata", None)
        labels = getattr(metadata, "labels", None) or {}
        if labels.get(_POOL_NAME_LABEL) != pool_name:
            return False
        for owner in getattr(metadata, "owner_references", None) or []:
            if (
                getattr(owner, "kind", None) == "Pool"
                and getattr(owner, "name", None) == pool_name
                and str(getattr(owner, "uid", "")) == pool_uid
                and getattr(owner, "controller", None) is True
            ):
                return True
        return False

    @staticmethod
    def _pod_ready(pod: Any) -> bool:
        pod_status = getattr(pod, "status", None)
        for condition in getattr(pod_status, "conditions", None) or []:
            if (
                getattr(condition, "type", None) == "Ready"
                and str(getattr(condition, "status", "")).lower() == "true"
            ):
                return True
        return False

    @staticmethod
    def _container_status(status_entry: Any) -> PoolMemberContainerStatus:
        container_state = getattr(status_entry, "state", None)
        state, reason = "unknown", None
        for name in ("waiting", "terminated", "running"):
            detail = getattr(container_state, name, None)
            if detail is not None:
                state = name
                candidate_reason = getattr(detail, "reason", None)
                reason = (
                    candidate_reason
                    if isinstance(candidate_reason, str) and candidate_reason
                    else None
                )
                break
        restart_count = getattr(status_entry, "restart_count", 0)
        return PoolMemberContainerStatus(
            name=str(getattr(status_entry, "name", "")),
            ready=getattr(status_entry, "ready", None) is True,
            restartCount=restart_count if isinstance(restart_count, int) else 0,
            state=state,
            reason=reason,
        )

    def _latest_event(self, pod: Any, namespace: str) -> Optional[PoolMemberEvent]:
        metadata = getattr(pod, "metadata", None)
        pod_name = str(getattr(metadata, "name", ""))
        if not pod_name:
            return None
        try:
            response = self._k8s_client.get_core_v1_api().list_namespaced_event(
                namespace=namespace,
                field_selector=f"involvedObject.name={pod_name}",
                limit=50,
            )
        except Exception:
            logger.warning("Failed to read Pool member events for %s", pod_name)
            return None
        events = list(getattr(response, "items", None) or [])
        if not events:
            return None
        event = max(events, key=self._event_sort_key)
        event_metadata = getattr(event, "metadata", None)
        observed_at = (
            getattr(event, "event_time", None)
            or getattr(event, "last_timestamp", None)
            or getattr(event, "first_timestamp", None)
            or getattr(event_metadata, "creation_timestamp", None)
        )
        return PoolMemberEvent(
            type=self._optional_string(getattr(event, "type", None)),
            reason=self._optional_string(getattr(event, "reason", None)),
            observedAt=str(observed_at) if observed_at is not None else None,
        )

    @staticmethod
    def _event_sort_key(event: Any) -> str:
        metadata = getattr(event, "metadata", None)
        observed_at = (
            getattr(event, "event_time", None)
            or getattr(event, "last_timestamp", None)
            or getattr(event, "first_timestamp", None)
            or getattr(metadata, "creation_timestamp", None)
        )
        return str(observed_at or "")

    @staticmethod
    def _optional_string(value: Any) -> Optional[str]:
        return value if isinstance(value, str) and value else None

    def _member_from_pod(self, pod: Any, namespace: str) -> PoolMemberResponse:
        metadata = getattr(pod, "metadata", None)
        pod_status = getattr(pod, "status", None)
        ready = self._pod_ready(pod)
        return PoolMemberResponse(
            name=str(getattr(metadata, "name", "")),
            phase=str(getattr(pod_status, "phase", None) or "Unknown"),
            ready=ready,
            containers=[
                self._container_status(entry)
                for entry in getattr(pod_status, "container_statuses", None) or []
            ],
            initContainers=[
                self._container_status(entry)
                for entry in getattr(pod_status, "init_container_statuses", None) or []
            ],
            latestEvent=None if ready else self._latest_event(pod, namespace),
        )

    def list_pools(self) -> ListPoolsResponse:
        """List all Pools in the configured namespace."""
        try:
            result = self._custom_api.list_namespaced_custom_object(
                group=OPENSANDBOX_API_GROUP,
                version=OPENSANDBOX_API_VERSION,
                namespace=self._namespace,
                plural=POOL_PLURAL,
            )
            items: List[PoolResponse] = [
                self._pool_from_raw(item) for item in result.get("items", [])
            ]
            return ListPoolsResponse(items=items)

        except ApiException as e:
            if e.status == 404:
                # CRD not installed — return empty list gracefully
                logger.warning("Pool CRD not found (404); returning empty list.")
                return ListPoolsResponse(items=[])
            logger.error(f"Kubernetes API error listing pools: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "code": SandboxErrorCodes.K8S_POOL_API_ERROR,
                    "message": f"Failed to list pools: {e.reason}",
                },
            ) from e
        except Exception as e:
            logger.error(f"Unexpected error listing pools: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "code": SandboxErrorCodes.K8S_POOL_API_ERROR,
                    "message": f"Failed to list pools: {e}",
                },
            ) from e

    def update_pool(self, pool_name: str, request: UpdatePoolRequest) -> PoolResponse:
        """Update the capacity configuration of an existing Pool."""
        patch_body = {
            "spec": {
                "capacitySpec": {
                    "bufferMax": request.capacity_spec.buffer_max,
                    "bufferMin": request.capacity_spec.buffer_min,
                    "poolMax": request.capacity_spec.pool_max,
                    "poolMin": request.capacity_spec.pool_min,
                }
            }
        }

        try:
            updated = self._custom_api.patch_namespaced_custom_object(
                group=OPENSANDBOX_API_GROUP,
                version=OPENSANDBOX_API_VERSION,
                namespace=self._namespace,
                plural=POOL_PLURAL,
                name=pool_name,
                body=patch_body,
            )
            logger.info(f"Updated pool capacity: name={pool_name}")
            return self._pool_from_raw(updated)

        except ApiException as e:
            if e.status == 404:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail={
                        "code": SandboxErrorCodes.K8S_POOL_NOT_FOUND,
                        "message": f"Pool '{pool_name}' not found.",
                    },
                ) from e
            logger.error(f"Kubernetes API error updating pool {pool_name}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "code": SandboxErrorCodes.K8S_POOL_API_ERROR,
                    "message": f"Failed to update pool: {e.reason}",
                },
            ) from e
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Unexpected error updating pool {pool_name}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "code": SandboxErrorCodes.K8S_POOL_API_ERROR,
                    "message": f"Failed to update pool: {e}",
                },
            ) from e

    def delete_pool(self, pool_name: str) -> None:
        """Delete a Pool resource."""
        try:
            self._custom_api.delete_namespaced_custom_object(
                group=OPENSANDBOX_API_GROUP,
                version=OPENSANDBOX_API_VERSION,
                namespace=self._namespace,
                plural=POOL_PLURAL,
                name=pool_name,
                grace_period_seconds=0,
            )
            logger.info(f"Deleted pool: name={pool_name}, namespace={self._namespace}")

        except ApiException as e:
            if e.status == 404:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail={
                        "code": SandboxErrorCodes.K8S_POOL_NOT_FOUND,
                        "message": f"Pool '{pool_name}' not found.",
                    },
                ) from e
            logger.error(f"Kubernetes API error deleting pool {pool_name}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "code": SandboxErrorCodes.K8S_POOL_API_ERROR,
                    "message": f"Failed to delete pool: {e.reason}",
                },
            ) from e
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Unexpected error deleting pool {pool_name}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "code": SandboxErrorCodes.K8S_POOL_API_ERROR,
                    "message": f"Failed to delete pool: {e}",
                },
            ) from e
