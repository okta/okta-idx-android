/*
 * Copyright 2025-Present Okta, Inc.
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
package com.okta.idx.kotlin.dto

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth.assertThat
import org.json.JSONException
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class IdxWebAuthnCapabilityTest {

    private val activationData = """
        {
          "rp": {
            "name": "testName"
          },
          "user": {
            "displayName": "test test",
            "name": "test@test.com",
            "id": "testId"
          },
          "pubKeyCredParams": [
            {
              "type": "public-key",
              "alg": -7
            },
            {
              "type": "public-key",
              "alg": -257
            }
          ],
          "challenge": "testChallnege",
          "attestation": "direct",
          "authenticatorSelection": {
            "userVerification": "preferred",
            "requireResidentKey": false
          },
          "u2fParams": {
            "appid": "https://test.test.test"
          },
          "excludeCredentials": [],
          "extensions": {
            "credProps": true
          }
        }
    """.trimIndent()

    private val challengeData = """
        {
            "challengeData": {
                "challenge": "testChallenge",
                "userVerification": "preferred",
                "extensions": {
                    "appid": "https://test.test.com"
                }
            }
        }
    """.trimIndent()

    @Test
    fun `publicKeyCredentialCreationOptions returns original data when rpId is null`() {
        // arrange
        val capability = IdxWebAuthnRegistrationCapability(activationData)

        // act
        val result = capability.publicKeyCredentialCreationOptions().getOrThrow()

        // assert
        assertThat(result).isEqualTo(activationData)
    }

    @Test
    fun `publicKeyCredentialCreationOptions returns original data when rpId is blank`() {
        // arrange
        val capability = IdxWebAuthnRegistrationCapability(activationData)

        // act
        val result = capability.publicKeyCredentialCreationOptions().getOrThrow()

        // assert
        assertThat(result).isEqualTo(activationData)
    }

    @Test
    fun `publicKeyCredentialCreationOptions overrides rpId when provided`() {
        // arrange
        val capability = IdxWebAuthnRegistrationCapability(activationData)
        val customRpId = "customRpId"

        // act
        val result = capability.publicKeyCredentialCreationOptions(customRpId).getOrThrow()

        // assert
        assertThat(JSONObject(result).getJSONObject("rp").getString("id")).isEqualTo(customRpId)
    }

    @Test
    fun `publicKeyCredentialCreationOptions returns failure on invalid JSON`() {
        // arrange
        val invalidData = "{invalidjson"
        val capability = IdxWebAuthnRegistrationCapability(invalidData)

        // act
        val result = capability.publicKeyCredentialCreationOptions("customRpId").exceptionOrNull()

        // assert
        assertThat(result is JSONException).isTrue()
    }

    @Test
    fun `challengeData returns original data when rpId is null`() {
        // arrange
        val capability = IdxWebAuthnAuthenticationCapability(challengeData)

        // act
        val result = capability.challengeData().getOrThrow()

        // assert
        assertThat(result).isEqualTo(challengeData)
    }

    @Test
    fun `challengeData returns original data when rpId is blank`() {
        // arrange
        val capability = IdxWebAuthnAuthenticationCapability(challengeData)

        // act
        val result = capability.challengeData().getOrThrow()

        // assert
        assertThat(result).isEqualTo(challengeData)
    }

    @Test
    fun `challengeData overrides rpId when provided`() {
        // arrange
        val capability = IdxWebAuthnAuthenticationCapability(challengeData)
        val customRpId = "customRpId"

        // act
        val result = capability.challengeData(customRpId).getOrThrow()

        // assert
        assertThat(JSONObject(result).getString("rpId")).isEqualTo(customRpId)
    }

    @Test
    fun `challengeData returns failure on invalid JSON`() {
        // arrange
        val invalidData = "{invalidjson"
        val capability = IdxWebAuthnAuthenticationCapability(invalidData)

        // act
        val result = capability.challengeData("customRpId").exceptionOrNull()

        // assert
        assertThat(result is JSONException).isTrue()
    }
}
