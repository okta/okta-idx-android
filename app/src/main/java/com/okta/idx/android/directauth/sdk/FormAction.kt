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
package com.okta.idx.android.directauth.sdk

import androidx.lifecycle.MutableLiveData
import com.okta.idx.android.directauth.sdk.forms.AuthenticateVerifyCodeForm
import com.okta.idx.android.directauth.sdk.forms.PasswordResetForm
import com.okta.idx.android.directauth.sdk.forms.RegisterPasswordForm
import com.okta.idx.android.directauth.sdk.forms.RegisterPhoneForm
import com.okta.idx.android.directauth.sdk.forms.RegisterSelectAuthenticatorForm
import com.okta.idx.android.directauth.sdk.forms.RegisterVerifyCodeForm
import com.okta.idx.android.directauth.sdk.forms.SelectAuthenticatorForm
import com.okta.idx.android.directauth.sdk.forms.SelectFactorForm
import com.okta.idx.android.directauth.sdk.forms.UsernamePasswordForm
import com.okta.idx.sdk.api.client.Authenticator
import com.okta.idx.sdk.api.client.IDXAuthenticationWrapper
import com.okta.idx.sdk.api.client.ProceedContext
import com.okta.idx.sdk.api.exception.ProcessingException
import com.okta.idx.sdk.api.model.AuthenticationStatus
import com.okta.idx.sdk.api.response.AuthenticationResponse
import com.okta.idx.sdk.api.response.TokenResponse
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import timber.log.Timber

/**
 * Used when a Form UI Action occurs to initiate transition to another state.
 */
data class FormAction internal constructor(
    private val viewModelScope: CoroutineScope,
    private val stateLiveData: MutableLiveData<State>,
    private val authenticationWrapper: IDXAuthenticationWrapper,
) {
    sealed class State {
        data class Data(
            val form: Form,
            val messages: List<String> = emptyList(),
        ) : State()

        object Loading : State()
        class Success(val tokenResponse: TokenResponse) : State()
        class FailedToLoad(val messages: List<String>) : State()
    }

    internal sealed class ProceedTransition {
        class TokenTransition(val tokenResponse: TokenResponse) : ProceedTransition()
        class FormTransition(val form: Form) : ProceedTransition()
        class ErrorTransition(val errors: List<String>) : ProceedTransition()
        class TerminalTransition(val errors: List<String>) : ProceedTransition()
    }

    internal class ProceedData(
        val authenticationWrapper: IDXAuthenticationWrapper,
        private val formAction: FormAction,
    ) {
        fun handleTerminalTransitions(response: AuthenticationResponse): ProceedTransition? {
            if (response.tokenResponse != null) {
                return ProceedTransition.TokenTransition(response.tokenResponse)
            }
            if (response.authenticationStatus == AuthenticationStatus.SKIP_COMPLETE) {
                return ProceedTransition.TerminalTransition(response.errors ?: emptyList())
            }
            if (response.errors.isNotEmpty()) {
                return ProceedTransition.ErrorTransition(response.errors)
            }
            return null
        }

        fun handleKnownTransitions(response: AuthenticationResponse): ProceedTransition? {
            handleTerminalTransitions(response)?.let { return it }

            return when (response.authenticationStatus) {
                AuthenticationStatus.AWAITING_PASSWORD_RESET -> {
                    passwordResetForm(response)
                }
                AuthenticationStatus.PASSWORD_EXPIRED -> {
                    passwordResetForm(response)
                }
                AuthenticationStatus.AWAITING_AUTHENTICATOR_SELECTION -> {
                    authenticateSelectAuthenticatorForm(response)
                }
                AuthenticationStatus.AWAITING_AUTHENTICATOR_ENROLLMENT -> {
                    registerVerifyForm(response)
                }
                AuthenticationStatus.AWAITING_AUTHENTICATOR_ENROLLMENT_DATA -> {
                    handleEnrollmentData(response)
                }
                AuthenticationStatus.AWAITING_AUTHENTICATOR_VERIFICATION -> {
                    verifyForm(response)
                }
                AuthenticationStatus.AWAITING_AUTHENTICATOR_VERIFICATION_DATA -> {
                    handleVerificationData(response)
                }
                else -> null
            }
        }

        fun registerSelectAuthenticatorForm(
            authenticators: List<Authenticator>,
            proceedContext: ProceedContext,
            formAction: FormAction
        ): ProceedTransition {
            val canSkip = authenticationWrapper.isSkipAuthenticatorPresent(proceedContext)

            return ProceedTransition.FormTransition(
                RegisterSelectAuthenticatorForm(
                    RegisterSelectAuthenticatorForm.ViewModel(
                        authenticators,
                        canSkip,
                        proceedContext
                    ),
                    formAction
                )
            )
        }

        fun authenticateSelectAuthenticatorForm(
            previousResponse: AuthenticationResponse
        ): ProceedTransition {
            val canSkip =
                authenticationWrapper.isSkipAuthenticatorPresent(previousResponse.proceedContext)

            return ProceedTransition.FormTransition(
                SelectAuthenticatorForm(
                    SelectAuthenticatorForm.ViewModel(
                        previousResponse.authenticators,
                        canSkip,
                        previousResponse.proceedContext
                    ),
                    formAction
                )
            )
        }

        private fun handleEnrollmentData(response: AuthenticationResponse): ProceedTransition {
            return if (response.currentAuthenticatorMethods.size == 1) {
                registerVerifyForm(response)
            } else {
                selectFactorForm(response)
            }
        }

        private fun selectFactorForm(response: AuthenticationResponse): ProceedTransition {
            val factors = response.authenticators.first().factors
            val canSkip = authenticationWrapper.isSkipAuthenticatorPresent(response.proceedContext)
            return ProceedTransition.FormTransition(
                SelectFactorForm(
                    viewModel = SelectFactorForm.ViewModel(
                        factors = factors,
                        canSkip = canSkip,
                        proceedContext = response.proceedContext,
                    ),
                    formAction = formAction,
                )
            )
        }

        private fun registerVerifyForm(response: AuthenticationResponse): ProceedTransition {
            return when (response.currentAuthenticatorMethods.first()) {
                "email" -> {
                    ProceedTransition.FormTransition(
                        RegisterVerifyCodeForm(
                            RegisterVerifyCodeForm.ViewModel(proceedContext = response.proceedContext),
                            formAction
                        )
                    )
                }
                "password" -> {
                    ProceedTransition.FormTransition(
                        RegisterPasswordForm(
                            RegisterPasswordForm.ViewModel(proceedContext = response.proceedContext),
                            formAction
                        )
                    )
                }
                "sms" -> {
                    ProceedTransition.FormTransition(
                        RegisterPhoneForm(
                            RegisterPhoneForm.ViewModel(
                                proceedContext = response.proceedContext,
                                factor = response.authenticators.first().factors.first()
                            ),
                            formAction
                        )
                    )
                }
                "voice" -> {
                    ProceedTransition.FormTransition(
                        RegisterPhoneForm(
                            RegisterPhoneForm.ViewModel(
                                proceedContext = response.proceedContext,
                                factor = response.authenticators.first().factors.first()
                            ),
                            formAction
                        )
                    )
                }
                else -> unsupportedPolicy()
            }
        }

        private fun passwordResetForm(response: AuthenticationResponse): ProceedTransition {
            return ProceedTransition.FormTransition(
                PasswordResetForm(
                    viewModel = PasswordResetForm.ViewModel(
                        proceedContext = response.proceedContext
                    ),
                    formAction = formAction,
                )
            )
        }

        private fun verifyForm(response: AuthenticationResponse): ProceedTransition {
            return ProceedTransition.FormTransition(
                AuthenticateVerifyCodeForm(
                    AuthenticateVerifyCodeForm.ViewModel(proceedContext = response.proceedContext),
                    formAction
                )
            )
        }

        private fun handleVerificationData(response: AuthenticationResponse): ProceedTransition {
            return if (response.currentAuthenticatorMethods.size == 1) {
                verifyForm(response)
            } else {
                selectFactorForm(response)
            }
        }

        fun unsupportedPolicy(): ProceedTransition {
            return ProceedTransition.TerminalTransition(listOf("Unsupported policy"))
        }

        suspend fun invokeTransitionFactory(transitionFactory: suspend ProceedData.() -> ProceedTransition): ProceedTransition {
            return transitionFactory()
        }
    }

    internal fun proceed(transitionFactory: suspend ProceedData.() -> ProceedTransition) {
        val initialState = stateLiveData.value as? State.Data ?: return

        stateLiveData.value = State.Loading

        val proceedData = ProceedData(authenticationWrapper, this)
        viewModelScope.launch(Dispatchers.IO) {
            try {
                proceedData
                    .invokeTransitionFactory(transitionFactory)
                    .handle(initialState)
            } catch (e: Exception) {
                Timber.e(e, "An error occurred.")
                stateLiveData.postValue(initialState.copy(messages = messagesFromException(e)))
            }
        }
    }

    internal fun transitionToForm(form: Form) {
        stateLiveData.value = State.Data(form)
    }

    private fun ProceedTransition.handle(initialState: State.Data) {
        when (this) {
            is ProceedTransition.TokenTransition -> {
                stateLiveData.postValue(State.Success(tokenResponse))
            }
            is ProceedTransition.ErrorTransition -> {
                stateLiveData.postValue(initialState.copy(messages = errors))
            }
            is ProceedTransition.FormTransition -> {
                stateLiveData.postValue(
                    State.Data(form)
                )
            }
            is ProceedTransition.TerminalTransition -> stateLiveData.postValue(
                State.Data(initialForm(), messages = errors)
            )
        }
    }

    private fun messagesFromException(e: Exception): List<String> {
        return when (e) {
            is ProcessingException -> {
                val messages = e.errorResponse.messages
                messages?.value?.map {
                    it.message
                } ?: listOf("An error occurred.")
            }
            else -> {
                listOf("An error occurred.")
            }
        }
    }

    fun signOut() {
        transitionToForm(initialForm())
    }

    fun skip(proceedContext: ProceedContext) {
        proceed {
            val response = authenticationWrapper.skipAuthenticatorEnrollment(proceedContext)
            handleKnownTransitions(response)?.let { return@proceed it }
            unsupportedPolicy()
        }
    }

    private fun initialForm(): Form {
        return UsernamePasswordForm(formAction = this)
    }
}
