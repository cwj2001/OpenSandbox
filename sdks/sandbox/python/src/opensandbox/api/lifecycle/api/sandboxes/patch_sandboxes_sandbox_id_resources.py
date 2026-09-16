#
# Copyright 2026 Alibaba Group Holding Ltd.
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
#

from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.error_response import ErrorResponse
from ...models.patch_sandbox_resources_request import PatchSandboxResourcesRequest
from ...models.patch_sandbox_resources_response import PatchSandboxResourcesResponse
from ...types import Response


def _get_kwargs(
    sandbox_id: str,
    *,
    body: PatchSandboxResourcesRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "patch",
        "url": "/sandboxes/{sandbox_id}/resources".format(
            sandbox_id=quote(str(sandbox_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ErrorResponse | PatchSandboxResourcesResponse | None:
    if response.status_code == 202:
        response_202 = PatchSandboxResourcesResponse.from_dict(response.json())

        return response_202

    if response.status_code == 400:
        response_400 = ErrorResponse.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = ErrorResponse.from_dict(response.json())

        return response_401

    if response.status_code == 403:
        response_403 = ErrorResponse.from_dict(response.json())

        return response_403

    if response.status_code == 404:
        response_404 = ErrorResponse.from_dict(response.json())

        return response_404

    if response.status_code == 409:
        response_409 = ErrorResponse.from_dict(response.json())

        return response_409

    if response.status_code == 422:
        response_422 = ErrorResponse.from_dict(response.json())

        return response_422

    if response.status_code == 500:
        response_500 = ErrorResponse.from_dict(response.json())

        return response_500

    if response.status_code == 501:
        response_501 = ErrorResponse.from_dict(response.json())

        return response_501

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorResponse | PatchSandboxResourcesResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    sandbox_id: str,
    *,
    client: AuthenticatedClient | Client,
    body: PatchSandboxResourcesRequest,
) -> Response[ErrorResponse | PatchSandboxResourcesResponse]:
    """Request an in-place CPU and memory resize

     Asynchronously updates the desired CPU and memory requests or limits for
    a running, non-pooled Kubernetes BatchSandbox. The controller applies the
    template change to the running Pod through Kubernetes' `resize`
    subresource; this endpoint returning `202` means only that the desired
    update was accepted, not that kubelet has completed it.

    This operation is unsupported for Pool-backed sandboxes, non-Kubernetes
    runtimes, GPU or other extended resources, and sandboxes that are not
    currently running. Kubernetes can defer or reject a resize according to
    node capacity, QoS and container runtime constraints.

    Args:
        sandbox_id (str):
        body (PatchSandboxResourcesRequest): Partial update for CPU and memory resource
            requirements. At least one of
            `resourceLimits` or `resourceRequests` is required. Each supplied map
            must be non-empty and may only contain `cpu` and `memory`; omitted keys
            retain their current values.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorResponse | PatchSandboxResourcesResponse]
    """

    kwargs = _get_kwargs(
        sandbox_id=sandbox_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    sandbox_id: str,
    *,
    client: AuthenticatedClient | Client,
    body: PatchSandboxResourcesRequest,
) -> ErrorResponse | PatchSandboxResourcesResponse | None:
    """Request an in-place CPU and memory resize

     Asynchronously updates the desired CPU and memory requests or limits for
    a running, non-pooled Kubernetes BatchSandbox. The controller applies the
    template change to the running Pod through Kubernetes' `resize`
    subresource; this endpoint returning `202` means only that the desired
    update was accepted, not that kubelet has completed it.

    This operation is unsupported for Pool-backed sandboxes, non-Kubernetes
    runtimes, GPU or other extended resources, and sandboxes that are not
    currently running. Kubernetes can defer or reject a resize according to
    node capacity, QoS and container runtime constraints.

    Args:
        sandbox_id (str):
        body (PatchSandboxResourcesRequest): Partial update for CPU and memory resource
            requirements. At least one of
            `resourceLimits` or `resourceRequests` is required. Each supplied map
            must be non-empty and may only contain `cpu` and `memory`; omitted keys
            retain their current values.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorResponse | PatchSandboxResourcesResponse
    """

    return sync_detailed(
        sandbox_id=sandbox_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    sandbox_id: str,
    *,
    client: AuthenticatedClient | Client,
    body: PatchSandboxResourcesRequest,
) -> Response[ErrorResponse | PatchSandboxResourcesResponse]:
    """Request an in-place CPU and memory resize

     Asynchronously updates the desired CPU and memory requests or limits for
    a running, non-pooled Kubernetes BatchSandbox. The controller applies the
    template change to the running Pod through Kubernetes' `resize`
    subresource; this endpoint returning `202` means only that the desired
    update was accepted, not that kubelet has completed it.

    This operation is unsupported for Pool-backed sandboxes, non-Kubernetes
    runtimes, GPU or other extended resources, and sandboxes that are not
    currently running. Kubernetes can defer or reject a resize according to
    node capacity, QoS and container runtime constraints.

    Args:
        sandbox_id (str):
        body (PatchSandboxResourcesRequest): Partial update for CPU and memory resource
            requirements. At least one of
            `resourceLimits` or `resourceRequests` is required. Each supplied map
            must be non-empty and may only contain `cpu` and `memory`; omitted keys
            retain their current values.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorResponse | PatchSandboxResourcesResponse]
    """

    kwargs = _get_kwargs(
        sandbox_id=sandbox_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    sandbox_id: str,
    *,
    client: AuthenticatedClient | Client,
    body: PatchSandboxResourcesRequest,
) -> ErrorResponse | PatchSandboxResourcesResponse | None:
    """Request an in-place CPU and memory resize

     Asynchronously updates the desired CPU and memory requests or limits for
    a running, non-pooled Kubernetes BatchSandbox. The controller applies the
    template change to the running Pod through Kubernetes' `resize`
    subresource; this endpoint returning `202` means only that the desired
    update was accepted, not that kubelet has completed it.

    This operation is unsupported for Pool-backed sandboxes, non-Kubernetes
    runtimes, GPU or other extended resources, and sandboxes that are not
    currently running. Kubernetes can defer or reject a resize according to
    node capacity, QoS and container runtime constraints.

    Args:
        sandbox_id (str):
        body (PatchSandboxResourcesRequest): Partial update for CPU and memory resource
            requirements. At least one of
            `resourceLimits` or `resourceRequests` is required. Each supplied map
            must be non-empty and may only contain `cpu` and `memory`; omitted keys
            retain their current values.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorResponse | PatchSandboxResourcesResponse
    """

    return (
        await asyncio_detailed(
            sandbox_id=sandbox_id,
            client=client,
            body=body,
        )
    ).parsed
