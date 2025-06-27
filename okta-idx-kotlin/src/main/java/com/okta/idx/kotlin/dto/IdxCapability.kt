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
package com.okta.idx.kotlin.dto

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import com.okta.authfoundation.client.OAuth2ClientResult
import com.okta.idx.kotlin.client.InteractionCodeFlow
import com.okta.idx.kotlin.dto.IdxRemediation.Type
import kotlinx.coroutines.delay
import okhttp3.HttpUrl
import okio.ByteString.Companion.decodeBase64
import org.json.JSONObject
import java.net.URI
import java.net.URISyntaxException

/**
 * Represents a collection of capabilities.
 */
class IdxCapabilityCollection<C> internal constructor(
    private val capabilities: Set<C>,
) : Set<C> by capabilities {
    /**
     * Returns a capability based on its type.
     */
    inline fun <reified Capability : C> get(): Capability? {
        val matched = firstOrNull { it is Capability } ?: return null
        return matched as Capability
    }
}

/** Describes the IdP associated with a remediation of type [Type.REDIRECT_IDP]. */
class IdxIdpCapability internal constructor(
    /** The IdPs id. */
    val id: String,
    /** The IdPs name. */
    val name: String,
    /** The IdPs redirectUrl. */
    val redirectUrl: HttpUrl,
) : IdxRemediation.Capability

/** Describes the poll action associated with an [IdxRemediation]. */
class IdxPollRemediationCapability internal constructor(
    /** The [IdxRemediation] associated with the poll action. */
    internal val remediation: IdxRemediation,

    /** The wait between each poll in milliseconds. */
    internal val wait: Int,
) : IdxRemediation.Capability {
    /** Available to allow testing without a real delay. */
    internal var delayFunction: suspend (Long) -> Unit = ::delay

    /**
     * Poll the IDX APIs with the configuration provided from the [IdxRemediation].
     *
     * All polling delay/retry logic is handled internally.
     *
     * @return the [OAuth2ClientResult] when the state changes.
     */
    suspend fun poll(flow: InteractionCodeFlow): OAuth2ClientResult<IdxResponse> {
        var result: OAuth2ClientResult<IdxResponse>
        var currentWait = wait
        var currentRemediation = remediation
        do {
            delayFunction(currentWait.toLong())
            result = flow.proceed(currentRemediation)
            if (result is OAuth2ClientResult.Error) {
                return result
            }
            val successResult = result as? OAuth2ClientResult.Success<IdxResponse>
            val remediations = successResult?.result?.remediations ?: return result

            var pollCapability: IdxPollRemediationCapability? = null

            for (r in remediations) {
                val capability = r.capabilities.get<IdxPollRemediationCapability>()
                if (capability != null) {
                    pollCapability = capability
                    break
                }
            }

            if (pollCapability == null) {
                return result
            }

            currentWait = pollCapability.wait
            currentRemediation = pollCapability.remediation
        } while (remediation.name == currentRemediation.name)
        return result
    }
}

/** Describes the recover action associated with an [IdxAuthenticator]. */
class IdxRecoverCapability internal constructor(
    /** The [IdxRemediation] associated with the recover action. */
    val remediation: IdxRemediation,
) : IdxAuthenticator.Capability

/** Describes the send action associated with an [IdxAuthenticator]. */
class IdxSendCapability internal constructor(
    /** The [IdxRemediation] associated with the send action. */
    val remediation: IdxRemediation,
) : IdxAuthenticator.Capability

/** Describes the resend action associated with an [IdxAuthenticator]. */
class IdxResendCapability internal constructor(
    /** The [IdxRemediation] associated with the resend action. */
    val remediation: IdxRemediation,
) : IdxAuthenticator.Capability

/** Describes the poll action associated with an [IdxAuthenticator]. */
class IdxPollAuthenticatorCapability internal constructor(
    /** The [IdxRemediation] associated with the poll action. */
    internal val remediation: IdxRemediation,
    /** The wait between each poll in milliseconds. */
    internal val wait: Int,
    /** The id of the authenticator */
    internal val authenticatorId: String?,
) : IdxAuthenticator.Capability {
    /** Available to allow testing without a real delay. */
    internal var delayFunction: suspend (Long) -> Unit = ::delay

    /**
     * Poll the IDX APIs with the configuration provided from the [IdxAuthenticator].
     *
     * All polling delay/retry logic is handled internally.
     *
     * @return the [OAuth2ClientResult] when the state changes.
     */
    suspend fun poll(flow: InteractionCodeFlow): OAuth2ClientResult<IdxResponse> {
        var result: OAuth2ClientResult<IdxResponse>
        var currentAuthenticatorId: String?
        var currentWait = wait
        var currentRemediation = remediation
        do {
            delayFunction(currentWait.toLong())
            result = flow.proceed(currentRemediation)
            if (result is OAuth2ClientResult.Error) {
                return result
            }
            val successResult = result as? OAuth2ClientResult.Success<IdxResponse>
            val currentAuthenticator = successResult?.result?.authenticators?.current ?: return result
            currentAuthenticatorId = currentAuthenticator.id
            val pollCapability = currentAuthenticator.capabilities.get<IdxPollAuthenticatorCapability>() ?: return result
            currentWait = pollCapability.wait
            currentRemediation = pollCapability.remediation
        } while (authenticatorId == currentAuthenticatorId)
        return result
    }
}

/** Describes the profile information associated with an [IdxAuthenticator]. */
class IdxProfileCapability internal constructor(
    /** Profile information describing the authenticator. This usually contains redacted information relevant to display to the user. */
    val profile: Map<String, String>,
) : IdxAuthenticator.Capability

/** Describes the TOTP information associated with an [IdxAuthenticator]. */
class IdxTotpCapability internal constructor(
    /** The base64 encoded image data associated with the QR code. */
    val imageData: String,

    /** The shared secret associated with the authenticator used for setup without a QR code. */
    val sharedSecret: String?
) : IdxAuthenticator.Capability {
    /** The [Bitmap] associated with the QR code TOTP registration information. */
    fun asImage(): Bitmap? {
        val bytes = imageData.substringAfter("data:image/png;base64,").decodeBase64()?.toByteArray() ?: return null
        return BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
    }
}

/**
 * Describes the WebAuthn registration capability associated with an [IdxAuthenticator].
 *
 * @property activationData The JSON string containing the public key credential creation options for WebAuthn activation.
 */
class IdxWebAuthnRegistrationCapability internal constructor(
    private val activationData: String,
) : IdxAuthenticator.Capability {

    /**
     * Returns the public key credential creation options as a JSON string.
     *
     * @param rpId Optional relying party ID. If provided and not blank, overrides the default `rp.id` in the activation data if present.
     * @return A [Result] containing the JSON string with the `rp.id` field set to [rpId] if specified, or the original activation data otherwise.
     */
    fun publicKeyCredentialCreationOptions(rpId: String? = null): Result<String> = runCatching {
        val rootObject = JSONObject(activationData)
        val rpObject = rootObject.getJSONObject("rp")

        // Determine the final rpId value. If rpId is provided and not blank, use it; otherwise, check for an existing "id" in the rp object.
        // If neither is available, check for "appid" in "u2fParams" and use its host as the rpId.
        if (!rpId.isNullOrBlank()) {
            rpObject.put("id", rpId)
        } else if (!rpObject.has("id")) {
            val derivedRpId = rpObject.optJSONObject("u2fParams")?.optString("appid")?.let { appId ->
                try {
                    URI(appId).host
                } catch (_: URISyntaxException) {
                    null
                }
            }
            derivedRpId?.let {
                rpObject.put("id", it)
            }
        }

        rootObject.toString()
    }
}

/**
 * Describes the WebAuthn authentication capability associated with an [IdxAuthenticator].
 *
 * @property challengeData The JSON string containing the public key credential creation options for WebAuthn activation.
 */
class IdxWebAuthnAuthenticationCapability internal constructor(
    private val _challengeData: String,
) : IdxAuthenticator.Capability {

    /**
     * Returns the challengeData.
     *
     * @param rpId Optional relying party ID. If provided and not blank, overrides the default `rpId` in the challenge data if present.
     * @return A [Result] containing the JSON string with the `rpId` field set to [rpId] if specified, or the original challenge data otherwise.
     */
    fun challengeData(rpId: String? = null): Result<String> = runCatching {

        val rootObject = JSONObject(_challengeData)

        // Determine the final rpId value. If rpId is provided and not blank, use it; otherwise, check for an existing "id" in the rp object.
        // If neither is available, check for "appid" in "extensions" and use its host as the rpId.
        if (!rpId.isNullOrBlank()) {
            rootObject.put("rpId", rpId)
        } else if (!rootObject.has("rpId")) {
            val derivedRpId = rootObject.optJSONObject("extensions")?.optString("appid")?.let { appId ->
                try {
                    URI(appId).host
                } catch (_: URISyntaxException) {
                    null
                }
            }
            derivedRpId?.let {
                rootObject.put("rpId", it)
            }
        }
        rootObject.toString()
    }
}

/** Describes the Number Challenge information associated with an [IdxAuthenticator]. */
class IdxNumberChallengeCapability internal constructor(
    /** The challenge the user is prompted to select. */
    val correctAnswer: String,
) : IdxAuthenticator.Capability

/** Describes the Password Settings associated with an [IdxAuthenticator]. */
class IdxPasswordSettingsCapability internal constructor(
    /** The associated [IdxPasswordSettingsCapability.Complexity] requirements. */
    val complexity: Complexity,
    /** The associated [IdxPasswordSettingsCapability.Age] requirements. */
    val age: Age? = null,
) : IdxAuthenticator.Capability {
    /** The associated password complexity requirements. */
    class Complexity internal constructor(
        /** The minimum length of the password. */
        val minLength: Int,
        /** The minimum number of lower case characters the password requires. */
        val minLowerCase: Int,
        /** The minimum number of upper case characters the password requires. */
        val minUpperCase: Int,
        /** The minimum number of number characters the password requires. */
        val minNumber: Int,
        /** The minimum number of symbol characters the password requires. */
        val minSymbol: Int,
        /** True if the password must exclude the username. */
        val excludeUsername: Boolean,
        /** The list of attributes the password must exclude. */
        val excludeAttributes: List<String>,
    )

    /** The associated password age requirements. */
    class Age internal constructor(
        /** The minimum number of minutes since the password was used. */
        val minAgeMinutes: Int,
        /** The number of previous iterations of the password that must not be used. */
        val historyCount: Int,
    )
}
