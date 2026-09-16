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

package opensandbox

import (
	"context"
	"io"
	"net/http"
	"testing"
)

func TestPatchSandboxResources(t *testing.T) {
	req := PatchSandboxResourcesRequest{
		ResourceLimits:   ResourceLimits{"cpu": "2", "memory": "2Gi"},
		ResourceRequests: ResourceLimits{"cpu": "1", "memory": "1Gi"},
	}

	_, client := newLifecycleServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("method = %s, want PATCH", r.Method)
		}
		if r.URL.EscapedPath() != "/sandboxes/sbx%2Fone%20two/resources" {
			t.Errorf("escaped path = %q, want %q", r.URL.EscapedPath(), "/sandboxes/sbx%2Fone%20two/resources")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		const wantBody = `{"resourceLimits":{"cpu":"2","memory":"2Gi"},"resourceRequests":{"cpu":"1","memory":"1Gi"}}`
		if string(body) != wantBody {
			t.Errorf("request body = %s, want %s", body, wantBody)
		}

		jsonResponse(w, http.StatusAccepted, PatchSandboxResourcesResponse{
			Generation:       3,
			ResourceLimits:   ResourceLimits{"cpu": "2", "memory": "2Gi"},
			ResourceRequests: ResourceLimits{"cpu": "1", "memory": "1Gi"},
		})
	})

	got, err := client.PatchSandboxResources(context.Background(), "sbx/one two", req)
	require.NoError(t, err)
	require.Equal(t, 3, got.Generation)
	require.Equal(t, req.ResourceLimits, got.ResourceLimits)
	require.Equal(t, req.ResourceRequests, got.ResourceRequests)
}

func TestPatchSandboxResourcesReturnsTransportError(t *testing.T) {
	_, client := newLifecycleServer(t, func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, http.StatusConflict, ErrorResponse{
			Code:    "RESOURCE_RESIZE_CONFLICT",
			Message: "resize is already in progress",
		})
	})

	_, err := client.PatchSandboxResources(context.Background(), "sbx-123", PatchSandboxResourcesRequest{
		ResourceLimits: ResourceLimits{"cpu": "2"},
	})
	require.Error(t, err)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, http.StatusConflict, apiErr.StatusCode)
}
