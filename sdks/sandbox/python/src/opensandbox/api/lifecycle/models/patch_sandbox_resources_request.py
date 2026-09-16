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

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.cpu_and_memory_resources import CPUAndMemoryResources


T = TypeVar("T", bound="PatchSandboxResourcesRequest")


@_attrs_define
class PatchSandboxResourcesRequest:
    """Partial update for CPU and memory resource requirements. At least one of
    `resourceLimits` or `resourceRequests` is required. Each supplied map
    must be non-empty and may only contain `cpu` and `memory`; omitted keys
    retain their current values.

        Attributes:
            resource_limits (CPUAndMemoryResources | Unset):
            resource_requests (CPUAndMemoryResources | Unset):
    """

    resource_limits: CPUAndMemoryResources | Unset = UNSET
    resource_requests: CPUAndMemoryResources | Unset = UNSET

    def to_dict(self) -> dict[str, Any]:
        resource_limits: dict[str, Any] | Unset = UNSET
        if not isinstance(self.resource_limits, Unset):
            resource_limits = self.resource_limits.to_dict()

        resource_requests: dict[str, Any] | Unset = UNSET
        if not isinstance(self.resource_requests, Unset):
            resource_requests = self.resource_requests.to_dict()

        field_dict: dict[str, Any] = {}

        field_dict.update({})
        if resource_limits is not UNSET:
            field_dict["resourceLimits"] = resource_limits
        if resource_requests is not UNSET:
            field_dict["resourceRequests"] = resource_requests

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.cpu_and_memory_resources import CPUAndMemoryResources

        d = dict(src_dict)
        _resource_limits = d.pop("resourceLimits", UNSET)
        resource_limits: CPUAndMemoryResources | Unset
        if isinstance(_resource_limits, Unset):
            resource_limits = UNSET
        else:
            resource_limits = CPUAndMemoryResources.from_dict(_resource_limits)

        _resource_requests = d.pop("resourceRequests", UNSET)
        resource_requests: CPUAndMemoryResources | Unset
        if isinstance(_resource_requests, Unset):
            resource_requests = UNSET
        else:
            resource_requests = CPUAndMemoryResources.from_dict(_resource_requests)

        patch_sandbox_resources_request = cls(
            resource_limits=resource_limits,
            resource_requests=resource_requests,
        )

        return patch_sandbox_resources_request
