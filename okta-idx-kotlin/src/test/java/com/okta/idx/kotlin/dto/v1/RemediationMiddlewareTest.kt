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
package com.okta.idx.kotlin.dto.v1

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.okta.idx.kotlin.dto.IdxAuthenticator
import com.okta.idx.kotlin.dto.IdxAuthenticatorCollection
import com.okta.idx.kotlin.dto.IdxCapabilityCollection
import com.okta.idx.kotlin.dto.IdxMessageCollection
import com.okta.idx.kotlin.dto.IdxRemediation
import com.okta.idx.kotlin.dto.IdxRemediation.Form
import com.okta.idx.kotlin.dto.IdxRemediation.Form.Field
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.hamcrest.CoreMatchers.instanceOf
import org.hamcrest.CoreMatchers.`is`
import org.hamcrest.CoreMatchers.notNullValue
import org.hamcrest.MatcherAssert.assertThat
import org.json.JSONException
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RemediationMiddlewareTest {

    private val remediationEmptyForm = IdxRemediation(
        type = IdxRemediation.Type.UNKNOWN,
        name = "test",
        form = Form(emptyList()),
        authenticators = IdxAuthenticatorCollection(emptyList()),
        capabilities = IdxCapabilityCollection(emptySet()),
        method = "method",
        href = "https://test.okta.com/idp/idx/identify".toHttpUrl(),
        accepts = null
    )

    private val attestationValue = "attestation-object"
    private val clientDataValue = "client-data-json"
    private val registrationResponseJson = """
{
  "rawId": "fakeRawId",
  "authenticatorAttachment": "platform",
  "type": "public-key",
  "id": "fakeId",
  "response": {
    "clientDataJSON": "$clientDataValue",
    "attestationObject": "$attestationValue",
    "transports": [
      "internal",
      "hybrid"
    ],
    "authenticatorData": "fakedata",
    "publicKeyAlgorithm": -7,
    "publicKey": "fakedPublicKey"
  },
  "clientExtensionResults": {
    "credProps": {
      "rk": true
    }
  }
}
    """.trimIndent()

    @Test
    fun `withRegistrationResponse sets attestation and clientData fields`() {
        // arrange
        val clientDataField = Field(
            name = "clientData",
            label = null,
            type = "string",
            _value = null,
            isVisible = true,
            isMutable = true,
            isRequired = false,
            isSecret = false,
            form = null,
            options = null,
            messages = IdxMessageCollection(emptyList()),
            authenticator = null
        )

        val attestationValueField = clientDataField.copy(name = "attestation")
        val credentialField = clientDataField.copy(name = "credentials", form = Form(listOf(attestationValueField, clientDataField)))

        val form = Form(listOf(credentialField))

        val remediation = IdxRemediation(
            type = IdxRemediation.Type.UNKNOWN,
            name = "test",
            form = form,
            authenticators = IdxAuthenticatorCollection(emptyList()),
            capabilities = IdxCapabilityCollection(emptySet()),
            method = "method",
            href = "https://test.okta.com/idp/idx/identify".toHttpUrl(),
            accepts = null
        )

        // act
        val updated = remediation.withRegistrationResponse(registrationResponseJson).getOrThrow()

        // assert
        assertThat(updated.form["credentials.attestation"]?.value, `is`(attestationValue))
        assertThat(updated.form["credentials.clientData"]?.value, `is`(clientDataValue))
    }

    @Test
    fun `withRegistrationResponse throws if attestation field missing`() {
        // arrange
        val form = Form(emptyList())
        val remediation = IdxRemediation(
            type = IdxRemediation.Type.UNKNOWN,
            name = "test",
            form = form,
            authenticators = IdxAuthenticatorCollection(emptyList()),
            capabilities = IdxCapabilityCollection(emptySet()),
            method = "method",
            href = "https://test.okta.com/idp/idx/identify".toHttpUrl(),
            accepts = null
        )

        // act
        val exception = remediation.withRegistrationResponse(registrationResponseJson).exceptionOrNull()

        // assert
        assertThat(exception, notNullValue())
        assertThat(exception, instanceOf(IllegalArgumentException::class.java))
        assertThat(exception?.message, `is`("The 'credentials.attestation' field is not present in the remediation form."))
    }

    @Test
    fun `withRegistrationResponse throws if clientData field missing`() {
        val attestationValueField = Field(
            name = "attestation",
            label = null,
            type = "string",
            _value = null,
            isVisible = true,
            isMutable = true,
            isRequired = false,
            isSecret = false,
            form = null,
            options = null,
            messages = IdxMessageCollection(emptyList()),
            authenticator = null
        )

        val credentialField = attestationValueField.copy(name = "credentials", form = Form(listOf(attestationValueField)))
        val remediation = IdxRemediation(
            type = IdxRemediation.Type.UNKNOWN,
            name = "test",
            form = Form(listOf(credentialField)),
            authenticators = IdxAuthenticatorCollection(emptyList()),
            capabilities = IdxCapabilityCollection(emptySet()),
            method = "method",
            href = "https://test.okta.com/idp/idx/identify".toHttpUrl(),
            accepts = null
        )
        val exception = remediation.withRegistrationResponse(registrationResponseJson).exceptionOrNull()

        // assert
        assertThat(exception, notNullValue())
        assertThat(exception, instanceOf(IllegalArgumentException::class.java))
        assertThat(exception?.message, `is`("The 'credentials.clientData' field is not present in the remediation form."))
    }

    @Test
    fun `withRegistrationResponse throws if registrationResponseJson is invalid json`() {
        // arrange
        val invalidJson = "invalid json"

        // act
        val exception = remediationEmptyForm.withRegistrationResponse(invalidJson).exceptionOrNull()

        // assert
        assertThat(exception, notNullValue())
        assertThat(exception, instanceOf(JSONException::class.java))
        assertThat(exception?.message, `is`("Value invalid of type java.lang.String cannot be converted to JSONObject"))
    }

    @Test
    fun `withRegistrationResponse throws if registrationResponseJson is missing response object`() {
        // arrange
        val missingResponse = JSONObject(registrationResponseJson).remove("response")?.toString() ?: error("Failed to remove response object")

        // act
        val exception = remediationEmptyForm.withRegistrationResponse(missingResponse).exceptionOrNull()

        // assert
        assertThat(exception, notNullValue())
        assertThat(exception, instanceOf(JSONException::class.java))
        assertThat(exception?.message, `is`("No value for response"))
    }

    @Test
    fun `withRegistrationResponse throws if registrationResponseJson is missing attestationObject field`() {
        // arrange
        val json = JSONObject(registrationResponseJson).apply {
            getJSONObject("response").remove("attestationObject")
        }.toString()

        // act
        val exception = remediationEmptyForm.withRegistrationResponse(json).exceptionOrNull()

        // assert
        assertThat(exception, notNullValue())
        assertThat(exception, instanceOf(JSONException::class.java))
        assertThat(exception?.message, `is`("No value for attestationObject"))
    }

    @Test
    fun `withRegistrationResponse throws if registrationResponseJson is missing clientDataJSON field`() {
        // arrange
        val json = JSONObject(registrationResponseJson).apply {
            getJSONObject("response").remove("clientDataJSON")
        }.toString()

        // act
        val exception = remediationEmptyForm.withRegistrationResponse(json).exceptionOrNull()

        // assert
        assertThat(exception, notNullValue())
        assertThat(exception, instanceOf(JSONException::class.java))
        assertThat(exception?.message, `is`("No value for clientDataJSON"))
    }

    @Test
    fun `withRegistrationResponse throws if attestationObject field is blank`() {
        // arrange
        val json = JSONObject(registrationResponseJson).apply {
            getJSONObject("response").put("attestationObject", " ")
        }.toString()

        // act
        val exception = remediationEmptyForm.withRegistrationResponse(json).exceptionOrNull()

        // assert
        assertThat(exception, notNullValue())
        assertThat(exception, instanceOf(IllegalArgumentException::class.java))
        assertThat(exception?.message, `is`("The 'attestationObject' field is not present in the create credential response."))
    }

    @Test
    fun `withRegistrationResponse throws if clientDataJSON field is blank`() {
        // arrange
        val json = JSONObject(registrationResponseJson).apply {
            getJSONObject("response").put("clientDataJSON", " ")
        }.toString()

        // act
        val exception = remediationEmptyForm.withRegistrationResponse(json).exceptionOrNull()

        // assert
        assertThat(exception, notNullValue())
        assertThat(exception, instanceOf(IllegalArgumentException::class.java))
        assertThat(exception?.message, `is`("The 'clientDataJSON' field is not present in the create credential response."))
    }

    fun Field.copy(
        name: String? = this.name,
        label: String? = this.label,
        type: String = this.type,
        value: Any? = this.value,
        isMutable: Boolean = this.isMutable,
        isRequired: Boolean = this.isRequired,
        isSecret: Boolean = this.isSecret,
        form: Form? = this.form,
        options: List<Field>? = this.options,
        messages: IdxMessageCollection = this.messages,
        authenticator: IdxAuthenticator? = this.authenticator,
        isVisible: Boolean = this.isVisible,
    ): Field {
        return Field(name, label, type, value, isMutable, isRequired, isSecret, form, options, messages, authenticator, isVisible)
    }
}
