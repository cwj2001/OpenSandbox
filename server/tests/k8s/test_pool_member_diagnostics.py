from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from opensandbox_server.services.constants import SandboxErrorCodes
from opensandbox_server.services.k8s.pool_service import PoolService


_POOL_NAME = "pool-a"
_POOL_UID = "pool-uid-a"
_POOL_LABEL = "sandbox.opensandbox.io/pool-name"


def _service() -> tuple[PoolService, MagicMock, MagicMock]:
    client = MagicMock()
    custom_api = MagicMock()
    core_api = MagicMock()
    client.get_custom_objects_api.return_value = custom_api
    client.get_core_v1_api.return_value = core_api
    return PoolService(client, namespace="sandbox-tenant-a"), custom_api, core_api


def _pool_raw(uid: str = _POOL_UID) -> dict:
    return {"metadata": {"name": _POOL_NAME, "uid": uid}}


def _container(name: str, *, ready: bool, waiting_reason: str | None = None):
    waiting = SimpleNamespace(reason=waiting_reason) if waiting_reason else None
    return SimpleNamespace(
        name=name,
        ready=ready,
        restart_count=2,
        state=SimpleNamespace(waiting=waiting, terminated=None, running=None),
    )


def _pod(name: str, *, ready: bool, owner_uid: str = _POOL_UID, owner_name: str = _POOL_NAME):
    return SimpleNamespace(
        metadata=SimpleNamespace(
            name=name,
            labels={_POOL_LABEL: _POOL_NAME},
            owner_references=[
                SimpleNamespace(kind="Pool", name=owner_name, uid=owner_uid, controller=True)
            ],
        ),
        status=SimpleNamespace(
            phase="Running" if ready else "Pending",
            conditions=[SimpleNamespace(type="Ready", status="True" if ready else "False")],
            container_statuses=[
                _container(
                    "sandbox", ready=ready, waiting_reason="ImagePullBackOff" if not ready else None
                )
            ],
            init_container_statuses=[
                _container(
                    "execd-installer",
                    ready=ready,
                    waiting_reason="ErrImagePull" if not ready else None,
                )
            ],
        ),
    )


def test_pool_member_diagnostics_filters_unverified_pods_and_omits_event_messages():
    service, custom_api, core_api = _service()
    custom_api.get_namespaced_custom_object.return_value = _pool_raw()
    healthy = _pod("member-ready", ready=True)
    warming = _pod("member-warming", ready=False)
    wrong_uid = _pod("forged-owner", ready=False, owner_uid="other-pool")
    service._k8s_client.list_pods.return_value = [warming, wrong_uid, healthy]
    core_api.list_namespaced_event.return_value = SimpleNamespace(
        items=[
            SimpleNamespace(
                type="Warning",
                reason="OldReason",
                event_time="2026-09-05T01:00:00Z",
                message="must not be exposed",
                metadata=SimpleNamespace(creation_timestamp=None),
            ),
            SimpleNamespace(
                type="Warning",
                reason="ImagePullBackOff",
                event_time="2026-09-05T02:00:00Z",
                message="credential-like text",
                metadata=SimpleNamespace(creation_timestamp=None),
            ),
        ]
    )

    response = service.get_pool_members(_POOL_NAME, limit=10)

    assert response.pool_name == _POOL_NAME
    assert response.member_count == 2
    assert response.truncated is False
    assert [member.name for member in response.members] == ["member-ready", "member-warming"]
    assert response.members[0].latest_event is None
    warming_member = response.members[1]
    assert warming_member.phase == "Pending"
    assert warming_member.containers[0].reason == "ImagePullBackOff"
    assert warming_member.init_containers[0].reason == "ErrImagePull"
    assert warming_member.latest_event.reason == "ImagePullBackOff"
    assert warming_member.latest_event.observed_at == "2026-09-05T02:00:00Z"
    assert not hasattr(warming_member.latest_event, "message")
    service._k8s_client.list_pods.assert_called_once_with(
        namespace="sandbox-tenant-a",
        label_selector=f"{_POOL_LABEL}={_POOL_NAME}",
        limit=11,
    )
    core_api.list_namespaced_event.assert_called_once_with(
        namespace="sandbox-tenant-a",
        field_selector="involvedObject.name=member-warming",
        limit=50,
    )


def test_pool_member_diagnostics_bounds_members_and_survives_event_read_failure():
    service, custom_api, core_api = _service()
    custom_api.get_namespaced_custom_object.return_value = _pool_raw()
    service._k8s_client.list_pods.return_value = [
        _pod("member-b", ready=False),
        _pod("member-a", ready=True),
    ]
    core_api.list_namespaced_event.side_effect = RuntimeError("RBAC denied")

    bounded = service.get_pool_members(_POOL_NAME, limit=1)

    assert bounded.member_count == 2
    assert bounded.truncated is True
    assert [member.name for member in bounded.members] == ["member-a"]
    core_api.list_namespaced_event.assert_not_called()

    full = service.get_pool_members(_POOL_NAME, limit=2)

    assert full.truncated is False
    assert full.members[1].latest_event is None
    core_api.list_namespaced_event.assert_called_once()


def test_pool_member_diagnostics_rejects_pool_without_owner_uid():
    service, custom_api, _ = _service()
    custom_api.get_namespaced_custom_object.return_value = _pool_raw(uid="")

    with pytest.raises(HTTPException) as exc_info:
        service.get_pool_members(_POOL_NAME, limit=1)

    assert exc_info.value.status_code == 500
    assert exc_info.value.detail["code"] == SandboxErrorCodes.K8S_POOL_API_ERROR


def test_pool_member_diagnostics_uses_current_tenant_namespace():
    from opensandbox_server.tenants.context import set_current_tenant
    from opensandbox_server.tenants.models import TenantEntry

    service, custom_api, _ = _service()
    custom_api.get_namespaced_custom_object.return_value = _pool_raw()
    service._k8s_client.list_pods.return_value = []
    set_current_tenant(TenantEntry(name="tenant-a", namespace="tenant-a-ns"))
    try:
        service.get_pool_members(_POOL_NAME, limit=1)
    finally:
        set_current_tenant(None)

    assert custom_api.get_namespaced_custom_object.call_args.kwargs["namespace"] == "tenant-a-ns"
    assert service._k8s_client.list_pods.call_args.kwargs["namespace"] == "tenant-a-ns"
