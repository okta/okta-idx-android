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

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import com.okta.idx.android.directauth.sdk.Form
import com.okta.idx.android.directauth.sdk.FormAction
import com.okta.idx.android.directauth.sdk.util.emitValidation
import com.okta.idx.sdk.api.model.UserProfile
import com.okta.idx.sdk.api.wrapper.AuthenticationWrapper

class RegisterForm internal constructor(
    val viewModel: ViewModel = ViewModel(),
    private val formAction: FormAction
) : Form {
    class ViewModel internal constructor(
        var lastName: String = "",
        var firstName: String = "",
        var primaryEmail: String = "",
    ) {
        private val _lastNameErrorsLiveData = MutableLiveData("")
        val lastNameErrorsLiveData: LiveData<String> = _lastNameErrorsLiveData

        private val _firstNameErrorsLiveData = MutableLiveData("")
        val firstNameErrorsLiveData: LiveData<String> = _firstNameErrorsLiveData

        private val _primaryEmailErrorsLiveData = MutableLiveData("")
        val primaryEmailErrorsLiveData: LiveData<String> = _primaryEmailErrorsLiveData

        fun isValid(): Boolean {
            val usernameValid = _lastNameErrorsLiveData.emitValidation { lastName.isNotEmpty() }
            val passwordValid = _firstNameErrorsLiveData.emitValidation { firstName.isNotEmpty() }
            val primaryEmailValid =
                _primaryEmailErrorsLiveData.emitValidation { primaryEmail.isNotEmpty() }
            return usernameValid && passwordValid && primaryEmailValid
        }
    }

    fun register() {
        if (!viewModel.isValid()) return

        formAction.proceed {
            val newUserRegistrationResponse = AuthenticationWrapper.fetchSignUpFormValues(idxClient)

            val userProfile = UserProfile()
            userProfile.addAttribute("lastName", viewModel.lastName)
            userProfile.addAttribute("firstName", viewModel.firstName)
            userProfile.addAttribute("email", viewModel.primaryEmail)

            val idxClientContext = newUserRegistrationResponse.idxClientContext

            val response = AuthenticationWrapper.register(idxClient, idxClientContext, userProfile)
            handleKnownTransitions(response)?.let { return@proceed it }

            registerSelectAuthenticatorForm(idxClientContext, formAction)
        }
    }

    fun signOut() {
        formAction.signOut()
    }
}