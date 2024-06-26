/*
 * Copyright 2022-Present Okta, Inc.
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
package com.okta.testing.network

import com.okta.authfoundation.client.IdTokenValidator
import com.okta.authfoundation.client.OAuth2Client
import com.okta.authfoundation.jwt.Jwt

class TestIdTokenValidator : IdTokenValidator {
    @Volatile lateinit var lastIdToken: Jwt
        private set
    @Volatile lateinit var lastIdTokenParameters: IdTokenValidator.Parameters
        private set

    override suspend fun validate(client: OAuth2Client, idToken: Jwt, parameters: IdTokenValidator.Parameters) {
        lastIdToken = idToken
        lastIdTokenParameters = parameters
    }
}
