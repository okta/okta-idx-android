/*
 * Copyright 2021-Present Okta, Inc.
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
package com.okta.idx.kotlin.client

/**
 * Describes the result from the IdxClient.
 */
sealed class IdxClientResult<T> {
    /** An error result. */
    class Error<T> internal constructor(val exception: Exception) : IdxClientResult<T>()
    /** Result with the expected response. */
    class Response<T> internal constructor(val response: T) : IdxClientResult<T>()
}
