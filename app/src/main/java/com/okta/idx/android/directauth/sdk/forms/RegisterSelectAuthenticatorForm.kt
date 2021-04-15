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
package com.okta.idx.android.directauth.sdk.forms

import com.okta.idx.android.directauth.sdk.Form
import com.okta.idx.android.directauth.sdk.FormAction
import com.okta.idx.sdk.api.model.IDXClientContext
import com.okta.idx.sdk.api.wrapper.AuthenticationWrapper

class RegisterSelectAuthenticatorForm internal constructor(
    val viewModel: ViewModel,
    private val formAction: FormAction,
) : Form {
    enum class RegisterType(internal val authenticatorType: String) {
        PASSWORD("password"), EMAIL("email");
    }

    class ViewModel internal constructor(
        val options: List<RegisterType>,
        internal val idxClientContext: IDXClientContext,
    )

    fun register(type: RegisterType) {
        formAction.proceed {
            val response = AuthenticationWrapper.enrollAuthenticator(
                idxClient,
                viewModel.idxClientContext,
                type.authenticatorType
            )
            handleKnownTransitions(response)?.let { return@proceed it }

            when (type) {
                RegisterType.EMAIL -> {
                    FormAction.ProceedTransition.FormTransition(
                        RegisterEmailForm(
                            RegisterEmailForm.ViewModel(idxClientContext = response.idxClientContext),
                            formAction
                        )
                    )
                }
                RegisterType.PASSWORD -> {
                    FormAction.ProceedTransition.FormTransition(
                        RegisterPasswordForm(
                            RegisterPasswordForm.ViewModel(idxClientContext = response.idxClientContext),
                            formAction
                        )
                    )
                }
            }
        }
    }

    fun signOut() {
        formAction.signOut()
    }
}
