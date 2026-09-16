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

if TYPE_CHECKING:
    from ..models.resource_limits import ResourceLimits


T = TypeVar("T", bound="PatchSandboxResourcesResponse")


@_attrs_define
class PatchSandboxResourcesResponse:
    """
    Attributes:
        generation (int): BatchSandbox generation carrying the desired resources.
        resource_limits (ResourceLimits): Runtime resource constraints as key-value pairs. Similar to Kubernetes
            resource specifications,
            allows flexible definition of resource limits. Common resource types include:
            - `cpu`: CPU allocation in millicores (e.g., "250m" for 0.25 CPU cores)
            - `memory`: Memory allocation in bytes or human-readable format (e.g., "512Mi", "1Gi")
            - `gpu`: Number of GPU devices (e.g., "1")

            New resource types can be added without API changes.
             Example: {'cpu': '500m', 'memory': '512Mi', 'gpu': '1'}.
        resource_requests (ResourceLimits): Runtime resource constraints as key-value pairs. Similar to Kubernetes
            resource specifications,
            allows flexible definition of resource limits. Common resource types include:
            - `cpu`: CPU allocation in millicores (e.g., "250m" for 0.25 CPU cores)
            - `memory`: Memory allocation in bytes or human-readable format (e.g., "512Mi", "1Gi")
            - `gpu`: Number of GPU devices (e.g., "1")

            New resource types can be added without API changes.
             Example: {'cpu': '500m', 'memory': '512Mi', 'gpu': '1'}.
    """

    generation: int
    resource_limits: ResourceLimits
    resource_requests: ResourceLimits

    def to_dict(self) -> dict[str, Any]:
        generation = self.generation

        resource_limits = self.resource_limits.to_dict()

        resource_requests = self.resource_requests.to_dict()

        field_dict: dict[str, Any] = {}

        field_dict.update(
            {
                "generation": generation,
                "resourceLimits": resource_limits,
                "resourceRequests": resource_requests,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.resource_limits import ResourceLimits

        d = dict(src_dict)
        generation = d.pop("generation")

        resource_limits = ResourceLimits.from_dict(d.pop("resourceLimits"))

        resource_requests = ResourceLimits.from_dict(d.pop("resourceRequests"))

        patch_sandbox_resources_response = cls(
            generation=generation,
            resource_limits=resource_limits,
            resource_requests=resource_requests,
        )

        return patch_sandbox_resources_response
