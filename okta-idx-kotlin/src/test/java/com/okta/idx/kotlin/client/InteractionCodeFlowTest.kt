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

import com.google.common.truth.Truth.assertThat
import com.okta.authfoundation.client.OAuth2Client
import com.okta.authfoundation.client.OAuth2ClientResult
import com.okta.authfoundation.credential.Token
import com.okta.idx.kotlin.dto.IdxRemediation
import com.okta.idx.kotlin.dto.IdxResponse
import com.okta.idx.kotlin.dto.createRemediation
import com.okta.testing.network.NetworkRule
import com.okta.testing.network.RequestMatchers.body
import com.okta.testing.network.RequestMatchers.bodyContaining
import com.okta.testing.network.RequestMatchers.path
import com.okta.testing.testBodyFromFile
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.SocketPolicy
import org.junit.Rule
import org.junit.Test

class InteractionCodeFlowTest {
    @get:Rule val networkRule = NetworkRule()

    @Test fun testStart(): Unit = runBlocking {
        networkRule.enqueue(path("/oauth2/default/v1/interact")) { response ->
            response.testBodyFromFile("client/interactResponse.json")
        }

        val clientResult = InteractionCodeFlow.create("test.okta.com/login") as OAuth2ClientResult.Success<InteractionCodeFlow>
        assertThat(clientResult.result.flowContext.interactionHandle).isEqualTo("029ZAB")
    }

    @Test fun testStartWithNoEndpoints(): Unit = runBlocking {
        networkRule.enqueue(path(".well-known/openid-configuration")) { response ->
            response.socketPolicy = SocketPolicy.DISCONNECT_AT_START
        }

        val client = OAuth2Client.createFromConfiguration(networkRule.configuration)
        val clientResult = InteractionCodeFlow.create("test.okta.com/login", client = client) as OAuth2ClientResult.Error<InteractionCodeFlow>
        assertThat(clientResult.exception).isInstanceOf(OAuth2ClientResult.Error.OidcEndpointsNotAvailableException::class.java)
    }

    @Test fun testStartWithExtraParameters(): Unit = runBlocking {
        networkRule.enqueue(
            path("/oauth2/default/v1/interact"),
            bodyContaining("&recovery_token=secret123")
        ) { response ->
            response.testBodyFromFile("client/interactResponse.json")
        }

        val extraParameters = mapOf(Pair("recovery_token", "secret123"))
        val clientResult = InteractionCodeFlow.create("test.okta.com/login", extraParameters) as OAuth2ClientResult.Success<InteractionCodeFlow>
        assertThat(clientResult.result.flowContext.interactionHandle).isEqualTo("029ZAB")
    }

    @Test fun testResume(): Unit = runBlocking {
        networkRule.enqueue(path("/oauth2/default/v1/interact")) { response ->
            response.testBodyFromFile("client/interactResponse.json")
        }
        val introspectBody = """{"interactionHandle":"029ZAB"}"""
        networkRule.enqueue(path("/idp/idx/introspect"), body(introspectBody)) { response ->
            response.testBodyFromFile("client/identifyRemediationResponse.json")
        }

        val clientResult = InteractionCodeFlow.create("test.okta.com/login") as OAuth2ClientResult.Success<InteractionCodeFlow>
        val client = clientResult.result
        assertThat(client.flowContext.interactionHandle).isEqualTo("029ZAB")

        val resumeResult = client.resume() as OAuth2ClientResult.Success<IdxResponse>
        assertThat(resumeResult.result.remediations).hasSize(4)
    }

    @Test fun testProceed(): Unit = runBlocking {
        networkRule.enqueue(path("/oauth2/default/v1/interact")) { response ->
            response.testBodyFromFile("client/interactResponse.json")
        }
        networkRule.enqueue(path("/idp/idx/introspect")) { response ->
            response.testBodyFromFile("client/identifyRemediationResponse.json")
        }
        val identifyBody = """{"identifier":"test@okta.com","credentials":{"passcode":"example"},"stateHandle":"029ZAB"}"""
        networkRule.enqueue(path("/idp/idx/identify"), body(identifyBody)) { response ->
            response.testBodyFromFile("client/successWithInteractionCodeResponse.json")
        }

        val clientResult = InteractionCodeFlow.create("test.okta.com/login") as OAuth2ClientResult.Success<InteractionCodeFlow>
        val client = clientResult.result
        assertThat(client.flowContext.interactionHandle).isEqualTo("029ZAB")

        val resumeResult = client.resume() as OAuth2ClientResult.Success<IdxResponse>
        val resumeResponse = resumeResult.result
        assertThat(resumeResponse.remediations).hasSize(4)

        val identifyRemediation = resumeResponse.remediations[0]
        identifyRemediation["identifier"]?.value = "test@okta.com"
        identifyRemediation["credentials.passcode"]?.value = "example"
        val proceedResult = client.proceed(identifyRemediation) as OAuth2ClientResult.Success<IdxResponse>
        assertThat(proceedResult.result.remediations[1].type).isEqualTo(IdxRemediation.Type.ISSUE)
    }

    @Test fun testProceedCopiesRemediationValues(): Unit = runBlocking {
        networkRule.enqueue(path("/oauth2/default/v1/interact")) { response ->
            response.testBodyFromFile("client/interactResponse.json")
        }
        networkRule.enqueue(path("/idp/idx/introspect")) { response ->
            response.testBodyFromFile("client/identifyRemediationResponse.json")
        }
        val identifyBody = """{"identifier":"test@okta.com","credentials":{"passcode":"example"},"stateHandle":"029ZAB"}"""
        networkRule.enqueue(path("/idp/idx/identify"), body(identifyBody)) { response ->
            response.testBodyFromFile("client/identifyRemediationResponse.json")
        }

        val clientResult = InteractionCodeFlow.create("test.okta.com/login") as OAuth2ClientResult.Success<InteractionCodeFlow>
        val client = clientResult.result
        assertThat(client.flowContext.interactionHandle).isEqualTo("029ZAB")

        val resumeResult = client.resume() as OAuth2ClientResult.Success<IdxResponse>
        val resumeResponse = resumeResult.result
        assertThat(resumeResponse.remediations).hasSize(4)

        val identifyRemediation = resumeResponse.remediations[0]
        identifyRemediation["identifier"]?.value = "test@okta.com"
        identifyRemediation["credentials.passcode"]?.value = "example"
        val proceedResult = client.proceed(identifyRemediation) as OAuth2ClientResult.Success<IdxResponse>
        val newIdentifyRemediation = proceedResult.result.remediations[0]
        assertThat(newIdentifyRemediation["identifier"]?.value).isEqualTo("test@okta.com")
        assertThat(newIdentifyRemediation["credentials.passcode"]?.value).isEqualTo("example")
    }

    @Test fun testExchangeCodes(): Unit = runBlocking {
        networkRule.enqueue(path("/oauth2/default/v1/interact")) { response ->
            response.testBodyFromFile("client/interactResponse.json")
        }
        networkRule.enqueue(path("/idp/idx/introspect")) { response ->
            response.testBodyFromFile("client/identifyRemediationResponse.json")
        }
        networkRule.enqueue(path("/idp/idx/identify")) { response ->
            response.testBodyFromFile("client/successWithInteractionCodeResponse.json")
        }
        networkRule.enqueue(path("/oauth2/v1/token")) { response ->
            response.testBodyFromFile("client/tokenResponse.json")
        }

        val clientResult = InteractionCodeFlow.create("test.okta.com/login") as OAuth2ClientResult.Success<InteractionCodeFlow>
        val client = clientResult.result
        assertThat(client.flowContext.interactionHandle).isEqualTo("029ZAB")

        val resumeResult = client.resume() as OAuth2ClientResult.Success<IdxResponse>
        val resumeResponse = resumeResult.result
        assertThat(resumeResponse.remediations).hasSize(4)

        val identifyRemediation = resumeResponse.remediations[0]
        identifyRemediation["identifier"]?.value = "test@okta.com"
        identifyRemediation["credentials.passcode"]?.value = "example"
        val proceedResult = client.proceed(identifyRemediation) as OAuth2ClientResult.Success<IdxResponse>
        val proceedResponse = proceedResult.result
        val issueRemediation = proceedResponse.remediations[1]
        assertThat(issueRemediation.type).isEqualTo(IdxRemediation.Type.ISSUE)

        val tokenResult = client.exchangeInteractionCodeForTokens(issueRemediation) as OAuth2ClientResult.Success<Token>
        assertThat(tokenResult.result.accessToken).isEqualTo("eyJraWQiOiJBaE1qU3VMQWdBTDJ1dHVVY2lFRWJ2R1JUbi1GRkt1Y2tVTDJibVZMVmp3IiwiYWxnIjoiUlMyNTYifQ.eyJ2ZXIiOjEsImp0aSI6IkFULm01N1NsVUpMRUQyT1RtLXVrUFBEVGxFY0tialFvYy1wVGxVdm5ha0k3T1Eub2FyNjFvOHVVOVlGVnBYcjYybzQiLCJpc3MiOiJodHRwczovL2Zvby5wcmV2aWV3LmNvbS9vYXV0aDIvZGVmYXVsdCIsImF1ZCI6ImFwaTovL2RlZmF1bHQiLCJpYXQiOjE2MDg1NjcwMTgsImV4cCI6MTYwODU3MDYxOCwiY2lkIjoiMG9henNtcHhacFZFZzRjaFMybzQiLCJ1aWQiOiIwMHUxMGt2dkZDMDZHT21odTJvNSIsInNjcCI6WyJvcGVuaWQiLCJwcm9maWxlIiwib2ZmbGluZV9hY2Nlc3MiXSwic3ViIjoiZm9vQG9rdGEuY29tIn0.lg2T8dKVfic_JU6qzNBqDuw3RFUq7Da5UO37eY3W-cOOb9UqijxGYj7d-z8qK1UJjRRcDg-rTMzYQbKCLVxjBw")
        assertThat(networkRule.idTokenValidator.lastIdTokenParameters.nonce).isEqualTo(client.flowContext.nonce)
        assertThat(networkRule.idTokenValidator.lastIdTokenParameters.maxAge).isNull()
    }

    @Test fun testExchangeCodesWithMaxAge(): Unit = runBlocking {
        networkRule.enqueue(path("/oauth2/default/v1/interact")) { response ->
            response.testBodyFromFile("client/interactResponse.json")
        }
        networkRule.enqueue(path("/idp/idx/introspect")) { response ->
            response.testBodyFromFile("client/identifyRemediationResponse.json")
        }
        networkRule.enqueue(path("/idp/idx/identify")) { response ->
            response.testBodyFromFile("client/successWithInteractionCodeResponse.json")
        }
        networkRule.enqueue(path("/oauth2/v1/token")) { response ->
            response.testBodyFromFile("client/tokenResponse.json")
        }

        val extraParameters = mapOf("max_age" to "65")
        val clientResult = InteractionCodeFlow.create(
            redirectUrl = "test.okta.com/login",
            extraStartRequestParameters = extraParameters,
        ) as OAuth2ClientResult.Success<InteractionCodeFlow>
        val client = clientResult.result
        assertThat(client.flowContext.interactionHandle).isEqualTo("029ZAB")

        val resumeResult = client.resume() as OAuth2ClientResult.Success<IdxResponse>
        val resumeResponse = resumeResult.result
        assertThat(resumeResponse.remediations).hasSize(4)

        val identifyRemediation = resumeResponse.remediations[0]
        identifyRemediation["identifier"]?.value = "test@okta.com"
        identifyRemediation["credentials.passcode"]?.value = "example"
        val proceedResult = client.proceed(identifyRemediation) as OAuth2ClientResult.Success<IdxResponse>
        val proceedResponse = proceedResult.result
        val issueRemediation = proceedResponse.remediations[1]
        assertThat(issueRemediation.type).isEqualTo(IdxRemediation.Type.ISSUE)

        val tokenResult = client.exchangeInteractionCodeForTokens(issueRemediation) as OAuth2ClientResult.Success<Token>
        assertThat(tokenResult.result.accessToken).isEqualTo("eyJraWQiOiJBaE1qU3VMQWdBTDJ1dHVVY2lFRWJ2R1JUbi1GRkt1Y2tVTDJibVZMVmp3IiwiYWxnIjoiUlMyNTYifQ.eyJ2ZXIiOjEsImp0aSI6IkFULm01N1NsVUpMRUQyT1RtLXVrUFBEVGxFY0tialFvYy1wVGxVdm5ha0k3T1Eub2FyNjFvOHVVOVlGVnBYcjYybzQiLCJpc3MiOiJodHRwczovL2Zvby5wcmV2aWV3LmNvbS9vYXV0aDIvZGVmYXVsdCIsImF1ZCI6ImFwaTovL2RlZmF1bHQiLCJpYXQiOjE2MDg1NjcwMTgsImV4cCI6MTYwODU3MDYxOCwiY2lkIjoiMG9henNtcHhacFZFZzRjaFMybzQiLCJ1aWQiOiIwMHUxMGt2dkZDMDZHT21odTJvNSIsInNjcCI6WyJvcGVuaWQiLCJwcm9maWxlIiwib2ZmbGluZV9hY2Nlc3MiXSwic3ViIjoiZm9vQG9rdGEuY29tIn0.lg2T8dKVfic_JU6qzNBqDuw3RFUq7Da5UO37eY3W-cOOb9UqijxGYj7d-z8qK1UJjRRcDg-rTMzYQbKCLVxjBw")
        assertThat(networkRule.idTokenValidator.lastIdTokenParameters.nonce).isEqualTo(client.flowContext.nonce)
        assertThat(networkRule.idTokenValidator.lastIdTokenParameters.maxAge).isEqualTo(65)
    }

    @Test fun testExchangeCodeWithWrongRemediationType(): Unit = runBlocking {
        networkRule.enqueue(path("/oauth2/default/v1/interact")) { response ->
            response.testBodyFromFile("client/interactResponse.json")
        }

        val clientResult = InteractionCodeFlow.create("test.okta.com/login") as OAuth2ClientResult.Success<InteractionCodeFlow>
        assertThat(clientResult.result.flowContext.interactionHandle).isEqualTo("029ZAB")

        val client = clientResult.result
        val exchangeCodesResult = client.exchangeInteractionCodeForTokens(createRemediation(emptyList())) as OAuth2ClientResult.Error<Token>
        assertThat(exchangeCodesResult.exception.message).isEqualTo("Invalid remediation.")
    }

    @Test fun testResumeWithValidNon200HttpCode(): Unit = runBlocking {
        networkRule.enqueue(path("/oauth2/default/v1/interact")) { response ->
            response.testBodyFromFile("client/interactResponse.json")
        }
        val introspectBody = """{"interactionHandle":"029ZAB"}"""
        networkRule.enqueue(path("/idp/idx/introspect"), body(introspectBody)) { response ->
            // IDX has valid body up to 499 status code
            response.testBodyFromFile("client/identifyRemediationResponse.json").setResponseCode(499)
        }

        val clientResult = InteractionCodeFlow.create("test.okta.com/login") as OAuth2ClientResult.Success<InteractionCodeFlow>
        val client = clientResult.result
        assertThat(client.flowContext.interactionHandle).isEqualTo("029ZAB")

        val resumeResult = client.resume() as OAuth2ClientResult.Success<IdxResponse>
        assertThat(resumeResult.result.remediations).hasSize(4)
    }

    @Test fun testResumeWithInvalidHttpCode(): Unit = runBlocking {
        networkRule.enqueue(path("/oauth2/default/v1/interact")) { response ->
            response.testBodyFromFile("client/interactResponse.json")
        }
        val introspectBody = """{"interactionHandle":"029ZAB"}"""
        networkRule.enqueue(path("/idp/idx/introspect"), body(introspectBody)) { response ->
            // IDX has valid body up to 499 status code
            response.testBodyFromFile("client/identifyRemediationResponse.json").setResponseCode(500)
        }

        val clientResult = InteractionCodeFlow.create("test.okta.com/login") as OAuth2ClientResult.Success<InteractionCodeFlow>
        val client = clientResult.result
        assertThat(client.flowContext.interactionHandle).isEqualTo("029ZAB")

        val resumeResult = client.resume() as OAuth2ClientResult.Error<IdxResponse>
        assertThat(resumeResult.exception.message).isEqualTo("HTTP Error: status code - 500")
    }
}
