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
package com.okta.idx.kotlin.dto.v1

import com.okta.idx.kotlin.dto.IdxAuthenticator
import com.okta.idx.kotlin.dto.IdxCapabilityCollection
import com.okta.idx.kotlin.dto.IdxNumberChallengeCapability
import com.okta.idx.kotlin.dto.IdxPasswordSettingsCapability
import com.okta.idx.kotlin.dto.IdxPollAuthenticatorCapability
import com.okta.idx.kotlin.dto.IdxProfileCapability
import com.okta.idx.kotlin.dto.IdxRecoverCapability
import com.okta.idx.kotlin.dto.IdxResendCapability
import com.okta.idx.kotlin.dto.IdxSecurityKeyChallengeCapability
import com.okta.idx.kotlin.dto.IdxSecurityKeyEnrollmentCapability
import com.okta.idx.kotlin.dto.IdxSendCapability
import com.okta.idx.kotlin.dto.IdxTotpCapability
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int

internal fun Response.toIdxAuthenticatorPathPairs(
    json: Json,
): List<AuthenticatorPathPair> {
    val result = mutableListOf<AuthenticatorPathPair>()
    currentAuthenticatorEnrollment?.value?.apply {
        result += toIdxAuthenticator(json, IdxAuthenticator.State.ENROLLING)
            .toPathPair("$.currentAuthenticatorEnrollment")
    }
    currentAuthenticator?.value?.apply {
        result += toIdxAuthenticator(json, IdxAuthenticator.State.AUTHENTICATING)
            .toPathPair("$.currentAuthenticator")
    }
    recoveryAuthenticator?.value?.apply {
        result += toIdxAuthenticator(json, IdxAuthenticator.State.RECOVERY)
            .toPathPair("$.recoveryAuthenticator")
    }
    authenticatorEnrollments?.value?.let {
        it.forEachIndexed { index, authenticator ->
            result += authenticator.toIdxAuthenticator(json, IdxAuthenticator.State.ENROLLED)
                .toPathPair("$.authenticatorEnrollments.value[$index]")
        }
    }
    authenticators?.value?.let {
        it.forEachIndexed { index, authenticator ->
            result += authenticator.toIdxAuthenticator(json, IdxAuthenticator.State.NORMAL)
                .toPathPair("$.authenticators.value[$index]")
        }
    }
    return result
}

internal fun Authenticator.toIdxAuthenticator(
    json: Json,
    state: IdxAuthenticator.State,
): IdxAuthenticator {
    val capabilities = mutableSetOf<IdxAuthenticator.Capability>()

    recover?.toIdxRemediation(json)?.let { capabilities += IdxRecoverCapability(it) }
    send?.toIdxRemediation(json)?.let { capabilities += IdxSendCapability(it) }
    resend?.toIdxRemediation(json)?.let { capabilities += IdxResendCapability(it) }
    poll?.toIdxRemediation(json)?.let { capabilities += IdxPollAuthenticatorCapability(it, poll.refresh?.toInt() ?: 0, id) }
    profile?.let { capabilities += IdxProfileCapability(it) }
    contextualData?.toTotpCapability()?.let { capabilities += it }
    contextualData?.toNumberChallengeCapability()?.let { capabilities += it }
    settings?.toIdxPasswordSettings()?.let { capabilities += it }
    contextualData?.toSecurityKeyEnrollmentCapability()?.let { capabilities += it }
    contextualData?.toSecurityKeyChallengeCapability()?.let { capabilities += it }

    return IdxAuthenticator(
        id = id,
        displayName = displayName,
        type = type.asIdxAuthenticatorType(),
        key = key,
        credentialId = credentialId,
        state = state,
        methods = methods.asIdxAuthenticatorMethods(),
        methodNames = methods.asMethodNames(),
        capabilities = IdxCapabilityCollection(capabilities),
    )
}

private fun String.asIdxAuthenticatorType(): IdxAuthenticator.Kind {
    return when (this) {
        "app" -> IdxAuthenticator.Kind.APP
        "email" -> IdxAuthenticator.Kind.EMAIL
        "phone" -> IdxAuthenticator.Kind.PHONE
        "password" -> IdxAuthenticator.Kind.PASSWORD
        "security_question" -> IdxAuthenticator.Kind.SECURITY_QUESTION
        "device" -> IdxAuthenticator.Kind.DEVICE
        "security_key" -> IdxAuthenticator.Kind.SECURITY_KEY
        "federated" -> IdxAuthenticator.Kind.FEDERATED
        else -> IdxAuthenticator.Kind.UNKNOWN
    }
}

private fun List<Map<String, String>>?.asIdxAuthenticatorMethods(): List<IdxAuthenticator.Method>? {
    if (this == null) return null
    val result = mutableListOf<IdxAuthenticator.Method>()
    for (map in this) {
        val type = map["type"]
        if (type != null) {
            result += type.asIdxAuthenticatorMethod()
        }
    }
    return result
}

private fun String.asIdxAuthenticatorMethod(): IdxAuthenticator.Method {
    return when (this) {
        "sms" -> IdxAuthenticator.Method.SMS
        "voice" -> IdxAuthenticator.Method.VOICE
        "email" -> IdxAuthenticator.Method.EMAIL
        "push" -> IdxAuthenticator.Method.PUSH
        "crypto" -> IdxAuthenticator.Method.CRYPTO
        "signedNonce" -> IdxAuthenticator.Method.SIGNED_NONCE
        "totp" -> IdxAuthenticator.Method.TOTP
        "password" -> IdxAuthenticator.Method.PASSWORD
        "webauthn" -> IdxAuthenticator.Method.WEB_AUTHN
        "security_question" -> IdxAuthenticator.Method.SECURITY_QUESTION
        else -> IdxAuthenticator.Method.UNKNOWN
    }
}

private fun List<Map<String, String>>?.asMethodNames(): List<String>? {
    if (this == null) return null
    val result = mutableListOf<String>()
    for (map in this) {
        val type = map["type"]
        if (type != null) {
            result += type
        }
    }
    return result
}

private fun Map<String, JsonElement>.toTotpCapability(): IdxAuthenticator.Capability? {
    val qrCode = get("qrcode") as? JsonObject? ?: return null
    val imageData = qrCode.stringValue("href") ?: return null
    val sharedSecret = (get("sharedSecret") as? JsonPrimitive?)?.content
    return IdxTotpCapability(imageData = imageData, sharedSecret = sharedSecret)
}

private fun Map<String, JsonElement>.toNumberChallengeCapability(): IdxAuthenticator.Capability? {
    val correctAnswer = get("correctAnswer") as? JsonPrimitive ?: return null
    return IdxNumberChallengeCapability(correctAnswer = correctAnswer.content)
}

private fun Authenticator.Settings.toIdxPasswordSettings(): IdxAuthenticator.Capability? {
    return IdxPasswordSettingsCapability(
        complexity = IdxPasswordSettingsCapability.Complexity(
            minLength = complexity.minLength,
            minLowerCase = complexity.minLowerCase,
            minUpperCase = complexity.minUpperCase,
            minNumber = complexity.minNumber,
            minSymbol = complexity.minSymbol,
            excludeUsername = complexity.excludeUsername,
            excludeAttributes = complexity.excludeAttributes,
        ),
        age = IdxPasswordSettingsCapability.Age(
            minAgeMinutes = age.minAgeMinutes,
            historyCount = age.historyCount,
        ),
    )
}

private fun Map<String, JsonElement>.toSecurityKeyEnrollmentCapability(): IdxAuthenticator.Capability? {
    val activationData = get("activationData") as? JsonObject? ?: return null
    val relyingParty = activationData["rp"] as? JsonObject? ?: return null
    val user = activationData["user"] as? JsonObject? ?: return null
    val publicKeyCredentialParameters =
        activationData["pubKeyCredParams"] as? JsonArray? ?: return null
    val authenticatorSelection =
        activationData["authenticatorSelection"] as? JsonObject? ?: return null
    val u2fParameters = activationData["u2fParams"] as? JsonObject? ?: return null
    val excludeCredentials = activationData["excludeCredentials"] as? JsonArray? ?: return null
    val challenge = activationData.stringValue("challenge")
    val attestation = activationData.stringValue("attestation")

    return IdxSecurityKeyEnrollmentCapability(
        challenge = challenge ?: return null,
        attestation = attestation ?: return null,
        relyingParty = relyingParty.asRelyingParty() ?: return null,
        user = user.asUser() ?: return null,
        publicKeyCredentialParameters = publicKeyCredentialParameters.asPublicKeyCredentialParameters()
            ?: return null,
        authenticatorSelection = authenticatorSelection.asAuthenticatorSelection() ?: return null,
        u2fParameters = u2fParameters.asU2fParameters() ?: return null,
        excludeCredentials = excludeCredentials.asExcludeCredentials() ?: return null
    )
}

private fun JsonObject.asRelyingParty(): IdxSecurityKeyEnrollmentCapability.RelyingParty? {
    return IdxSecurityKeyEnrollmentCapability.RelyingParty(
        name = stringValue("name") ?: return null,
    )
}

private fun JsonObject.asUser(): IdxSecurityKeyEnrollmentCapability.User? {
    return IdxSecurityKeyEnrollmentCapability.User(
        id = stringValue("id") ?: return null,
        name = stringValue("name") ?: return null,
        displayName = stringValue("displayName") ?: return null,
    )
}

private fun JsonArray.asPublicKeyCredentialParameters(): List<IdxSecurityKeyEnrollmentCapability.PublicKeyCredentialParameter>? {
    return map { jsonElement ->
        val jsonObject = jsonElement as? JsonObject? ?: return null
        jsonObject.asPublicKeyCredentialParameter() ?: return null
    }
}

private fun JsonObject.asPublicKeyCredentialParameter(): IdxSecurityKeyEnrollmentCapability.PublicKeyCredentialParameter? {
    val type = stringValue("type") ?: return null
    val algorithm = get("alg") as? JsonPrimitive? ?: return null
    return IdxSecurityKeyEnrollmentCapability.PublicKeyCredentialParameter(
        type = type,
        algorithm = algorithm.int,
    )
}

private fun JsonObject.asAuthenticatorSelection(): IdxSecurityKeyEnrollmentCapability.AuthenticatorSelection? {
    val userVerification = stringValue("userVerification") ?: return null
    val requireResidentKey = get("requireResidentKey") as? JsonPrimitive? ?: return null
    return IdxSecurityKeyEnrollmentCapability.AuthenticatorSelection(
        userVerification = userVerification,
        requireResidentKey = requireResidentKey.boolean,
    )
}

private fun JsonObject.asU2fParameters(): IdxSecurityKeyEnrollmentCapability.U2fParameters? {
    val appId = stringValue("appid") ?: return null
    return IdxSecurityKeyEnrollmentCapability.U2fParameters(
        appId = appId,
    )
}

private fun JsonArray.asExcludeCredentials(): List<IdxSecurityKeyEnrollmentCapability.ExcludeCredential>? {
    return map { jsonElement ->
        val jsonObject = jsonElement as? JsonObject? ?: return null
        jsonObject.asExcludeCredential() ?: return null
    }
}

private fun JsonObject.asExcludeCredential(): IdxSecurityKeyEnrollmentCapability.ExcludeCredential? {
    val transports = get("transports") as? JsonArray? ?: return null
    return IdxSecurityKeyEnrollmentCapability.ExcludeCredential(
        id = stringValue("id") ?: return null,
        type = stringValue("type") ?: return null,
        transport = transports.asTransportList() ?: return null
    )
}

private fun JsonArray.asTransportList(): List<String>? {
    return map { jsonElement ->
        val jsonPrimitive = jsonElement as? JsonPrimitive? ?: return null
        jsonPrimitive.content
    }
}

private fun Map<String, JsonElement>.toSecurityKeyChallengeCapability(): IdxAuthenticator.Capability? {
    val challengeData = get("challengeData") as? JsonObject? ?: return null
    val extensions = challengeData["extensions"] as? JsonObject? ?: return null

    return IdxSecurityKeyChallengeCapability(
        challenge = challengeData.stringValue("challenge") ?: return null,
        userVerification = challengeData.stringValue("userVerification") ?: return null,
        appId = extensions.stringValue("appid") ?: return null,
    )
}

private fun JsonObject.stringValue(key: String): String? {
    return (get(key) as? JsonPrimitive?)?.content
}
