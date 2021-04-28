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
package com.okta.idx.android.directauth.sdk.viewFactories

import android.view.View
import android.view.ViewGroup
import com.okta.idx.android.databinding.FormRegisterSelectAuthenticatorBinding
import com.okta.idx.android.databinding.RowFactorBinding
import com.okta.idx.android.directauth.sdk.FormViewFactory
import com.okta.idx.android.directauth.sdk.forms.RegisterSelectAuthenticatorForm
import com.okta.idx.android.directauth.sdk.models.AuthenticatorType
import com.okta.idx.android.directauth.sdk.util.inflateBinding

internal class RegisterSelectAuthenticatorFormViewFactory :
    FormViewFactory<RegisterSelectAuthenticatorForm> {
    override fun createUi(
        references: FormViewFactory.References,
        form: RegisterSelectAuthenticatorForm
    ): View {
        val binding =
            references.parent.inflateBinding(FormRegisterSelectAuthenticatorBinding::inflate)

        for (option in form.viewModel.options) {
            binding.root.addView(option.createView(binding.root, form), binding.root.childCount - 2)
        }

        binding.skipButton.visibility = if (form.viewModel.canSkip) View.VISIBLE else View.GONE
        binding.skipButton.setOnClickListener {
            form.skip()
        }

        binding.signOutButton.setOnClickListener {
            form.signOut()
        }

        return binding.root
    }

    private fun AuthenticatorType.createView(
        parent: ViewGroup,
        form: RegisterSelectAuthenticatorForm
    ): View {
        val binding = parent.inflateBinding(RowFactorBinding::inflate)
        binding.typeTextView.text = toString()
        binding.selectButton.setOnClickListener {
            form.register(this)
        }
        return binding.root
    }
}
