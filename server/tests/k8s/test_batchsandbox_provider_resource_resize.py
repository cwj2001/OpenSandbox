from unittest.mock import MagicMock

import pytest

from opensandbox_server.services.k8s.batchsandbox_provider import BatchSandboxProvider


def _running_batchsandbox() -> dict:
    return {
        "metadata": {"name": "sbx-1", "resourceVersion": "12"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "sandbox",
                            "resources": {
                                "limits": {"cpu": "500m", "memory": "512Mi", "nvidia.com/gpu": "1"},
                                "requests": {
                                    "cpu": "250m",
                                    "memory": "256Mi",
                                    "nvidia.com/gpu": "1",
                                },
                                "claims": [{"name": "gpu-claim"}],
                            },
                        },
                        {"name": "egress", "resources": {"limits": {"cpu": "100m"}}},
                    ]
                }
            }
        },
        "status": {"phase": "Succeed"},
    }


def test_patch_sandbox_resources_uses_resource_versioned_json_patch() -> None:
    k8s_client = MagicMock()
    provider = BatchSandboxProvider(k8s_client)
    provider.get_workload = MagicMock(return_value=_running_batchsandbox())
    k8s_client.patch_custom_object.return_value = {"metadata": {"generation": "4"}}

    provider.patch_sandbox_resources(
        sandbox_id="sbx-1",
        namespace="sandbox-ns",
        resource_limits={"cpu": "1"},
        resource_requests={"memory": "512Mi"},
    )

    k8s_client.patch_custom_object.assert_called_once_with(
        group="sandbox.opensandbox.io",
        version="v1alpha1",
        namespace="sandbox-ns",
        plural="batchsandboxes",
        name="sbx-1",
        content_type="application/json-patch+json",
        body=[
            {"op": "test", "path": "/metadata/resourceVersion", "value": "12"},
            {
                "op": "add",
                "path": "/spec/template/spec/containers/0/resources",
                "value": {
                    "limits": {"cpu": "1", "memory": "512Mi", "nvidia.com/gpu": "1"},
                    "requests": {"cpu": "250m", "memory": "512Mi", "nvidia.com/gpu": "1"},
                    "claims": [{"name": "gpu-claim"}],
                },
            },
        ],
    )


@pytest.mark.parametrize(
    ("workload", "error"),
    [
        ({"spec": {"poolRef": "warm"}, "status": {"phase": "Succeed"}}, NotImplementedError),
        ({"spec": {}, "status": {"phase": "Pending"}}, ValueError),
    ],
)
def test_patch_sandbox_resources_rejects_unsupported_or_nonrunning_workload(
    workload: dict, error: type[Exception]
) -> None:
    provider = BatchSandboxProvider(MagicMock())
    provider.get_workload = MagicMock(return_value=workload)

    with pytest.raises(error):
        provider.patch_sandbox_resources("sbx-1", "sandbox-ns", {"cpu": "1"}, None)
