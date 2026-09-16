/*
 * Copyright 2026 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.alibaba.opensandbox.sandbox.domain.models.sandboxes

/** Requested partial CPU and memory resize for a running sandbox. */
class SandboxResourcePatch private constructor(
    val resourceLimits: Map<String, String>?,
    val resourceRequests: Map<String, String>?,
) {
    companion object {
        @JvmStatic
        fun builder(): Builder = Builder()
    }

    class Builder {
        private var resourceLimits: Map<String, String>? = null
        private var resourceRequests: Map<String, String>? = null

        fun resourceLimits(resourceLimits: Map<String, String>): Builder {
            this.resourceLimits = resourceLimits.toMap()
            return this
        }

        fun resourceRequests(resourceRequests: Map<String, String>): Builder {
            this.resourceRequests = resourceRequests.toMap()
            return this
        }

        fun build(): SandboxResourcePatch {
            validateResources("resourceLimits", resourceLimits)
            validateResources("resourceRequests", resourceRequests)
            require(!resourceLimits.isNullOrEmpty() || !resourceRequests.isNullOrEmpty()) {
                "At least one of resourceLimits or resourceRequests must be non-empty"
            }
            return SandboxResourcePatch(resourceLimits, resourceRequests)
        }

        private fun validateResources(
            name: String,
            resources: Map<String, String>?,
        ) {
            if (resources == null) return
            require(resources.isNotEmpty()) { "$name must not be empty when specified" }
            require(resources.keys.all { it == "cpu" || it == "memory" }) {
                "$name may only contain cpu and memory"
            }
            require(resources.values.all { it.isNotBlank() }) {
                "$name values must not be blank"
            }
        }
    }
}

/** Desired resource values accepted in a new BatchSandbox generation. */
class SandboxResourcePatchResponse(
    val generation: Int,
    val resourceLimits: Map<String, String>,
    val resourceRequests: Map<String, String>,
)