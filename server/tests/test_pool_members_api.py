from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from opensandbox_server.api.schema import (
    PoolMemberContainerStatus,
    PoolMemberEvent,
    PoolMemberResponse,
    PoolMembersResponse,
)


_POOL_SERVICE_PATCH = "opensandbox_server.api.pool._get_pool_service"


def test_get_pool_members_returns_owner_verified_projection(client: TestClient, auth_headers: dict):
    service = MagicMock()
    service.get_pool_members.return_value = PoolMembersResponse(
        poolName="pool-a",
        memberCount=1,
        truncated=False,
        members=[
            PoolMemberResponse(
                name="pool-a-0",
                phase="Pending",
                ready=False,
                containers=[
                    PoolMemberContainerStatus(
                        name="sandbox",
                        ready=False,
                        restartCount=0,
                        state="waiting",
                        reason="ImagePullBackOff",
                    )
                ],
                latestEvent=PoolMemberEvent(
                    type="Warning",
                    reason="ImagePullBackOff",
                    observedAt="2026-09-05T02:00:00Z",
                ),
            )
        ],
    )

    with patch(_POOL_SERVICE_PATCH, return_value=service):
        response = client.get("/pools/pool-a/members?limit=7", headers=auth_headers)

    assert response.status_code == 200
    assert response.json() == {
        "poolName": "pool-a",
        "memberCount": 1,
        "truncated": False,
        "members": [
            {
                "name": "pool-a-0",
                "phase": "Pending",
                "ready": False,
                "containers": [
                    {
                        "name": "sandbox",
                        "ready": False,
                        "restartCount": 0,
                        "state": "waiting",
                        "reason": "ImagePullBackOff",
                    }
                ],
                "initContainers": [],
                "latestEvent": {
                    "type": "Warning",
                    "reason": "ImagePullBackOff",
                    "observedAt": "2026-09-05T02:00:00Z",
                },
            }
        ],
    }
    service.get_pool_members.assert_called_once_with("pool-a", 7)


def test_get_pool_members_rejects_unbounded_limit(client: TestClient, auth_headers: dict):
    response = client.get("/pools/pool-a/members?limit=101", headers=auth_headers)

    assert response.status_code == 422
