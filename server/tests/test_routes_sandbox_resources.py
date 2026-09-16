from fastapi import HTTPException
from fastapi.testclient import TestClient

from opensandbox_server.api import lifecycle
from opensandbox_server.api.schema import PatchSandboxResourcesResponse


def test_patch_sandbox_resources_accepts_cpu_and_memory_changes(
    client: TestClient,
    auth_headers: dict,
    monkeypatch,
) -> None:
    calls = []

    class StubService:
        @staticmethod
        def patch_sandbox_resources(sandbox_id: str, request) -> PatchSandboxResourcesResponse:
            calls.append((sandbox_id, request.resource_limits.root, request.resource_requests.root))
            return PatchSandboxResourcesResponse(
                generation=7,
                resourceLimits={"cpu": "1", "memory": "1Gi"},
                resourceRequests={"cpu": "500m", "memory": "512Mi"},
            )

    monkeypatch.setattr(lifecycle, "sandbox_service", StubService())

    response = client.patch(
        "/v1/sandboxes/sbx-001/resources",
        headers=auth_headers,
        json={"resourceLimits": {"cpu": "1"}, "resourceRequests": {"memory": "512Mi"}},
    )

    assert response.status_code == 202
    assert response.json() == {
        "generation": 7,
        "resourceLimits": {"cpu": "1", "memory": "1Gi"},
        "resourceRequests": {"cpu": "500m", "memory": "512Mi"},
    }
    assert calls == [("sbx-001", {"cpu": "1"}, {"memory": "512Mi"})]


def test_patch_sandbox_resources_rejects_non_cpu_memory_keys(
    client: TestClient, auth_headers: dict
) -> None:
    response = client.patch(
        "/v1/sandboxes/sbx-001/resources",
        headers=auth_headers,
        json={"resourceLimits": {"gpu": "1"}},
    )

    assert response.status_code == 422


def test_patch_sandbox_resources_propagates_runtime_error(
    client: TestClient,
    auth_headers: dict,
    monkeypatch,
) -> None:
    class StubService:
        @staticmethod
        def patch_sandbox_resources(sandbox_id: str, request) -> PatchSandboxResourcesResponse:
            raise HTTPException(
                status_code=501,
                detail={
                    "code": "SANDBOX::API_NOT_SUPPORTED",
                    "message": "This sandbox runtime does not support in-place resource resize.",
                },
            )

    monkeypatch.setattr(lifecycle, "sandbox_service", StubService())

    response = client.patch(
        "/v1/sandboxes/sbx-001/resources",
        headers=auth_headers,
        json={"resourceLimits": {"cpu": "1"}},
    )

    assert response.status_code == 501
    assert response.json()["code"] == "SANDBOX::API_NOT_SUPPORTED"
