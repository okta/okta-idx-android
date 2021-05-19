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

class TableOfContentsForm internal constructor(
    private val formAction: FormAction
) : Form {
    fun login() {
        formAction.proceed {
            val response = authenticationWrapper.begin()
            handleTerminalTransitions(response)?.let { return@proceed it }
            FormAction.ProceedTransition.FormTransition(
                form = UsernamePasswordForm(
                    formAction = formAction,
                    viewModel = UsernamePasswordForm.ViewModel(
                        socialIdps = response.idps ?: emptyList()
                    )
                ),
                proceedContext = response.proceedContext
            )
        }
    }

    fun register() {
        formAction.proceed {
            val response = authenticationWrapper.begin()
            handleTerminalTransitions(response)?.let { return@proceed it }
            FormAction.ProceedTransition.FormTransition(
                RegisterForm(
                    formAction = formAction,
                    viewModel = RegisterForm.ViewModel(),
                ),
                proceedContext = response.proceedContext
            )
        }
    }
}