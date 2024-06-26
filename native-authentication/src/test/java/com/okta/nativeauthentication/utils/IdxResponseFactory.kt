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
package com.okta.nativeauthentication.utils

import android.net.Uri
import com.okta.authfoundation.client.OAuth2ClientResult
import com.okta.idx.kotlin.client.InteractionCodeFlow
import com.okta.idx.kotlin.dto.IdxResponse
import com.okta.testing.network.NetworkRule
import com.okta.testing.network.RequestMatchers.path
import com.okta.testing.testBodyFromFile
import kotlinx.coroutines.runBlocking

internal class IdxResponseFactory(private val networkRule: NetworkRule) {
    fun fromJson(json: String): IdxResponse = runBlocking {
        networkRule.enqueue(path("/oauth2/default/v1/interact")) { response ->
            response.testBodyFromFile("SuccessInteractResponse.json")
        }
        networkRule.enqueue(path("/idp/idx/introspect")) { response ->
            response.setBody(json)
        }
        val interactionCodeFlow = InteractionCodeFlow().apply { start(Uri.parse("test.okta.com/login")) }
        (interactionCodeFlow.resume() as OAuth2ClientResult.Success<IdxResponse>).result
    }
}
