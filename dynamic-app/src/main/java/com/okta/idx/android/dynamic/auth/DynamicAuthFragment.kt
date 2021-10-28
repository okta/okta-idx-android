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
package com.okta.idx.android.dynamic.auth

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.graphics.Color
import android.os.Bundle
import android.text.method.PasswordTransformationMethod
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.RadioGroup
import android.widget.Toast
import androidx.activity.result.ActivityResult
import androidx.activity.result.IntentSenderRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat.getSystemService
import androidx.core.view.iterator
import androidx.fragment.app.viewModels
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import androidx.navigation.fragment.findNavController
import androidx.navigation.fragment.navArgs
import com.google.android.gms.fido.Fido
import com.google.android.gms.fido.fido2.api.common.AuthenticationExtensions
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAssertionResponse
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAttestationResponse
import com.google.android.gms.fido.fido2.api.common.AuthenticatorErrorResponse
import com.google.android.gms.fido.fido2.api.common.AuthenticatorSelectionCriteria
import com.google.android.gms.fido.fido2.api.common.FidoAppIdExtension
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredential
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialCreationOptions
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialParameters
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRequestOptions
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRpEntity
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialUserEntity
import com.google.android.gms.fido.fido2.api.common.UserVerificationMethodExtension
import com.google.android.material.textfield.TextInputLayout
import com.okta.idx.android.dynamic.BuildConfig
import com.okta.idx.android.dynamic.R
import com.okta.idx.android.dynamic.databinding.ErrorBinding
import com.okta.idx.android.dynamic.databinding.ErrorFieldBinding
import com.okta.idx.android.dynamic.databinding.FormActionPrimaryBinding
import com.okta.idx.android.dynamic.databinding.FormCheckBoxBinding
import com.okta.idx.android.dynamic.databinding.FormImageBinding
import com.okta.idx.android.dynamic.databinding.FormLabelBinding
import com.okta.idx.android.dynamic.databinding.FormOptionBinding
import com.okta.idx.android.dynamic.databinding.FormOptionNestedBinding
import com.okta.idx.android.dynamic.databinding.FormOptionsBinding
import com.okta.idx.android.dynamic.databinding.FormTextBinding
import com.okta.idx.android.dynamic.databinding.FragmentDynamicAuthBinding
import com.okta.idx.android.dynamic.databinding.LoadingBinding
import com.okta.idx.android.util.BaseFragment
import com.okta.idx.android.util.bindText
import com.okta.idx.android.util.inflateBinding
import kotlinx.coroutines.launch
import kotlinx.coroutines.tasks.await
import okhttp3.HttpUrl.Companion.toHttpUrl
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.toByteString

internal class DynamicAuthFragment : BaseFragment<FragmentDynamicAuthBinding>(
    FragmentDynamicAuthBinding::inflate
) {
    private val args: DynamicAuthFragmentArgs by navArgs()

    private val viewModel by viewModels<DynamicAuthViewModel>(factoryProducer = {
        object : ViewModelProvider.Factory {
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                return DynamicAuthViewModel(args.recoveryToken) as T
            }
        }
    })

    private val createCredentialIntentLauncher = registerForActivityResult(
        ActivityResultContracts.StartIntentSenderForResult(),
        ::handleCreateCredentialEnrollmentResult
    )

    private val challengeCredentialIntentLauncher = registerForActivityResult(
        ActivityResultContracts.StartIntentSenderForResult(),
        ::handleChallengeCredentialResult
    )

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        viewModel.state.observe(viewLifecycleOwner) { state ->
            when (state) {
                is DynamicAuthState.Form -> {
                    addMessageViews(state.messages)
                    // If there are dynamic fields, remove current view, iterate through fields, and render them.
                    binding.formContent.removeAllViews()
                    for (field in state.fields) {
                        binding.formContent.addView(field.createView())
                    }
                }
                is DynamicAuthState.Error -> {
                    addErrorView()
                }
                DynamicAuthState.Loading -> {
                    addLoadingView()
                }
                // If login is success, update the `TokenViewModel` and switch to `DashboardFragment`.
                DynamicAuthState.Tokens -> {
                    findNavController().navigate(DynamicAuthFragmentDirections.dynamicAuthToDashboard())
                }
            }
        }
    }

    private fun addMessageViews(messages: List<String>) {
        val parent = binding.messagesContent
        parent.visibility = if (messages.isEmpty()) View.GONE else View.VISIBLE
        parent.removeAllViews()
        for (message in messages) {
            val binding = parent.inflateBinding(ErrorFieldBinding::inflate)
            binding.errorTextView.text = message
            binding.errorTextView.setTextColor(Color.RED)
            parent.addView(binding.root)
        }
    }

    private fun addErrorView() {
        val parent = binding.formContent
        parent.removeAllViews()
        val binding = parent.inflateBinding(ErrorBinding::inflate)
        binding.button.setOnClickListener {
            viewModel.resume()
        }
        parent.addView(binding.root)
    }

    private fun addLoadingView() {
        binding.messagesContent.removeAllViews()
        val parent = binding.formContent
        parent.removeAllViews()
        val binding = parent.inflateBinding(LoadingBinding::inflate)
        parent.addView(binding.root)
    }

    /**
     * Create a `View` to render the `DynamicAuthField`.
     */
    private fun DynamicAuthField.createView(): View {
        return when (this) {
            // Render text fields.
            is DynamicAuthField.Text -> {
                val textBinding = binding.formContent.inflateBinding(FormTextBinding::inflate)

                textBinding.textInputLayout.hint = label

                if (isSecure) {
                    // Set properties for password or sensitive fields.
                    textBinding.textInputLayout.endIconMode = TextInputLayout.END_ICON_PASSWORD_TOGGLE
                    textBinding.editText.inputType = EditorInfo.TYPE_TEXT_VARIATION_PASSWORD
                    textBinding.editText.transformationMethod = PasswordTransformationMethod.getInstance()
                }

                bindText(
                    editText = textBinding.editText,
                    textInputLayout = textBinding.textInputLayout,
                    valueField = ::value,
                    errorsLiveData = errorsLiveData,
                    viewLifecycleOwner = viewLifecycleOwner,
                )

                textBinding.root
            }
            // Render checkboxes.
            is DynamicAuthField.CheckBox -> {
                val actionBinding = binding.formContent.inflateBinding(FormCheckBoxBinding::inflate)
                actionBinding.checkbox.text = label
                actionBinding.checkbox.isChecked = value
                actionBinding.checkbox.setOnCheckedChangeListener { _, isChecked ->
                    value = isChecked
                }
                actionBinding.root
            }
            // Render actions as buttons.
            is DynamicAuthField.Action -> {
                val actionBinding = binding.formContent.inflateBinding(FormActionPrimaryBinding::inflate)
                actionBinding.button.text = label
                actionBinding.button.setOnClickListener { onClick(requireContext()) }
                actionBinding.root
            }
            // Render radio groups for authenticator selection.
            is DynamicAuthField.Options -> {
                fun showSelectedContent(group: RadioGroup) {
                    for (view in group) {
                        val tagOption = view.getTag(R.id.option) as? DynamicAuthField.Options.Option?
                        if (tagOption != null) {
                            val nestedContentView = view.getTag(R.id.nested_content) as View
                            nestedContentView.visibility = if (tagOption == option) {
                                View.VISIBLE
                            } else {
                                View.GONE
                            }
                        }
                    }
                }

                val optionsBinding = binding.formContent.inflateBinding(FormOptionsBinding::inflate)
                optionsBinding.labelTextView.text = label
                optionsBinding.labelTextView.visibility = if (label == null) View.GONE else View.VISIBLE
                for (option in options) {
                    val optionBinding = optionsBinding.radioGroup.inflateBinding(
                        FormOptionBinding::inflate, attachToParent = true
                    )
                    optionBinding.radioButton.id = View.generateViewId()
                    optionBinding.radioButton.text = option.label
                    optionBinding.radioButton.setTag(R.id.option, option)
                    val nestedContentBinding =
                        optionsBinding.radioGroup.inflateBinding(FormOptionNestedBinding::inflate, attachToParent = true)
                    optionBinding.radioButton.setTag(R.id.nested_content, nestedContentBinding.root)
                    for (field in option.fields) {
                        nestedContentBinding.nestedContent.addView(field.createView())
                    }
                }
                optionsBinding.radioGroup.setOnCheckedChangeListener { group, checkedId ->
                    val radioButton = group.findViewById<View>(checkedId)
                    option = radioButton.getTag(R.id.option) as DynamicAuthField.Options.Option
                    showSelectedContent(group)
                }

                errorsLiveData.observe(viewLifecycleOwner) {
                    optionsBinding.errorTextView.text = it
                    optionsBinding.errorTextView.visibility = if (it.isNullOrEmpty()) View.GONE else View.VISIBLE
                }

                showSelectedContent(optionsBinding.radioGroup)
                optionsBinding.root
            }
            // Render image for authenticator QR code.
            is DynamicAuthField.Image -> {
                val imageBinding = binding.formContent.inflateBinding(FormImageBinding::inflate)
                imageBinding.labelTextView.text = label
                imageBinding.imageView.setImageBitmap(bitmap)
                if (sharedSecret != null) {
                    imageBinding.imageView.setOnLongClickListener {
                        val clipboard = getSystemService(requireContext(), ClipboardManager::class.java)
                        val clip = ClipData.newPlainText(sharedSecret, sharedSecret)
                        clipboard?.setPrimaryClip(clip)
                        Toast.makeText(requireContext(), "Shared secret copied to clipboard.", Toast.LENGTH_LONG).show()
                        true
                    }
                }
                imageBinding.root
            }
            // Render labels.
            is DynamicAuthField.Label -> {
                val binding = binding.formContent.inflateBinding(FormLabelBinding::inflate)
                binding.labelTextView.text = label
                binding.root
            }
            is DynamicAuthField.SecurityKeyEnrollment -> {
                val actionBinding = binding.formContent.inflateBinding(FormActionPrimaryBinding::inflate)
                actionBinding.button.text = "Register biometric"
                actionBinding.button.setOnClickListener {
                    val fido2ApiClient = Fido.getFido2ApiClient(binding.formContent.context)
                    val options = PublicKeyCredentialCreationOptions.Builder()
                        .setChallenge(trait.challenge.decodeBase64()?.toByteArray())
                        .setAuthenticatorSelection(
                            AuthenticatorSelectionCriteria.Builder()
                                .setRequireResidentKey(trait.authenticatorSelection.requireResidentKey)
                                .build()
                        )
                        .setParameters(
                            trait.publicKeyCredentialParameters.map {
                                PublicKeyCredentialParameters(it.type, it.algorithm)
                            }
                        )
                        .setRp(
                            PublicKeyCredentialRpEntity(
                                BuildConfig.ISSUER.toHttpUrl().host,
                                trait.relyingParty.name,
                                null,
                            )
                        )
                        .setUser(
                            PublicKeyCredentialUserEntity(
                                trait.user.id.toByteArray(),
                                trait.user.name,
                                null,
                                trait.user.displayName,
                            )
                        )
                        .build()
                    val task = fido2ApiClient.getRegisterPendingIntent(options)
                    lifecycleScope.launch {
                        val intent = task.await()
                        createCredentialIntentLauncher.launch(
                            IntentSenderRequest.Builder(intent).build()
                        )
                    }
                }
                actionBinding.root
            }
            is DynamicAuthField.SecurityKeyChallenge -> {
                // TODO: I've never tested this.
                val actionBinding = binding.formContent.inflateBinding(FormActionPrimaryBinding::inflate)
                actionBinding.button.text = "Verify biometric"
                actionBinding.button.setOnClickListener {
                    val fido2ApiClient = Fido.getFido2ApiClient(binding.formContent.context)
                    val options = PublicKeyCredentialRequestOptions.Builder()
                        .setChallenge(trait.challenge.decodeBase64()?.toByteArray())
                        .setRpId(BuildConfig.ISSUER.toHttpUrl().host)
//                    .setAllowList(PublicKeyCredentialDescriptor())
                        .setAuthenticationExtensions(
                            AuthenticationExtensions.Builder()
                                .setFido2Extension(FidoAppIdExtension(trait.appId))
                                .setUserVerificationMethodExtension(
                                    UserVerificationMethodExtension(trait.userVerification != "discouraged")
                                )
                                .build()
                        )
                        .build()
                    val task = fido2ApiClient.getSignPendingIntent(options)
                    lifecycleScope.launch {
                        val intent = task.await()
                        challengeCredentialIntentLauncher.launch(
                            IntentSenderRequest.Builder(intent).build()
                        )
                    }
                }
                actionBinding.root
            }
        }
    }

    private fun handleCreateCredentialEnrollmentResult(activityResult: ActivityResult) {
        val bytes = activityResult.data?.getByteArrayExtra(Fido.FIDO2_KEY_CREDENTIAL_EXTRA)
        when {
            activityResult.resultCode != Activity.RESULT_OK ->
                Toast.makeText(requireContext(), "Cancelled", Toast.LENGTH_LONG).show()
            bytes == null ->
                Toast.makeText(requireContext(), "Credential Error", Toast.LENGTH_LONG)
                    .show()
            else -> {
                val credential = PublicKeyCredential.deserializeFromBytes(bytes)
                val response = credential.response
                if (response is AuthenticatorErrorResponse) {
                    Toast.makeText(requireContext(), response.errorMessage, Toast.LENGTH_LONG)
                        .show()
                } else {
                    handlePublicKeyCredentialEnrollment(credential)
                }
            }
        }
    }

    private fun handleChallengeCredentialResult(activityResult: ActivityResult) {
        val bytes = activityResult.data?.getByteArrayExtra(Fido.FIDO2_KEY_CREDENTIAL_EXTRA)
        when {
            activityResult.resultCode != Activity.RESULT_OK ->
                Toast.makeText(requireContext(), "Cancelled", Toast.LENGTH_LONG).show()
            bytes == null ->
                Toast.makeText(requireContext(), "Credential Error", Toast.LENGTH_LONG)
                    .show()
            else -> {
                val credential = PublicKeyCredential.deserializeFromBytes(bytes)
                val response = credential.response
                if (response is AuthenticatorErrorResponse) {
                    Toast.makeText(requireContext(), response.errorMessage, Toast.LENGTH_LONG)
                        .show()
                } else {
                    handlePublicKeyCredentialChallenge(credential)
                }
            }
        }
    }

    // TODO: I'm guessing much of this file can be de-duped.
    private fun handlePublicKeyCredentialEnrollment(credential: PublicKeyCredential) {
        val state = viewModel.state.value as? DynamicAuthState.Form? ?: return
        val field = state.fields.firstOrNull { it is DynamicAuthField.SecurityKeyEnrollment } ?: return
        val securityKeyEnrollment = field as? DynamicAuthField.SecurityKeyEnrollment ?: return
        val response = credential.response as? AuthenticatorAttestationResponse ?: return

        val attestation = response.attestationObject.toBase64()
        val clientData = response.clientDataJSON.toBase64()
        securityKeyEnrollment.remediation["credentials.attestation"]?.value = attestation
        securityKeyEnrollment.remediation["credentials.clientData"]?.value = clientData

        securityKeyEnrollment.onComplete()
    }

    private fun handlePublicKeyCredentialChallenge(credential: PublicKeyCredential) {
        val state = viewModel.state.value as? DynamicAuthState.Form? ?: return
        val field = state.fields.firstOrNull { it is DynamicAuthField.SecurityKeyChallenge } ?: return
        val securityKeyChallenge = field as? DynamicAuthField.SecurityKeyChallenge ?: return
        val response = credential.response as? AuthenticatorAssertionResponse ?: return

        val authenticatorData = response.authenticatorData.toBase64()
        val clientData = response.clientDataJSON.toBase64()
        val signatureData = response.signature.toBase64()
        securityKeyChallenge.remediation["credentials.authenticatorData"]?.value = authenticatorData
        securityKeyChallenge.remediation["credentials.clientData"]?.value = clientData
        securityKeyChallenge.remediation["credentials.signatureData"]?.value = signatureData

        securityKeyChallenge.onComplete()
    }

    private fun ByteArray.toBase64(): String {
        return toByteString().base64Url().removeSuffix("=")
    }
}
