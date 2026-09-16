// Copyright 2026 Alibaba Group Holding Ltd.
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

using OpenSandbox.Models;

namespace OpenSandbox.Services;

/// <summary>
/// Optional lifecycle capability for requesting an in-place sandbox resource resize.
/// </summary>
public interface ISandboxResourceResizer
{
    /// <summary>
    /// Requests an asynchronous update to a sandbox's CPU and memory resources.
    /// </summary>
    /// <param name="sandboxId">The sandbox ID.</param>
    /// <param name="request">The requested CPU and memory limits or reservations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The desired resources accepted for a new sandbox generation.</returns>
    /// <exception cref="OpenSandbox.Core.InvalidArgumentException">Thrown when request values are invalid.</exception>
    /// <exception cref="OpenSandbox.Core.SandboxException">Thrown when the sandbox service request fails.</exception>
    Task<PatchSandboxResourcesResponse> PatchSandboxResourcesAsync(
        string sandboxId,
        PatchSandboxResourcesRequest request,
        CancellationToken cancellationToken = default);
}
