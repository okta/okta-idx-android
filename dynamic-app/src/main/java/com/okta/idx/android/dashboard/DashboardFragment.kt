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
package com.okta.idx.android.dashboard

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.Button
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.ExperimentalUnitApi
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.TextUnitType
import androidx.compose.ui.unit.dp
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.navigation.fragment.findNavController
import com.google.android.material.composethemeadapter.MdcTheme
import com.okta.authfoundation.InternalAuthFoundationApi
import com.okta.authfoundation.client.internal.performRequest
import com.okta.authfoundation.credential.Token
import com.okta.authfoundationbootstrap.CredentialBootstrap
import com.okta.idx.android.dynamic.R
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch

internal class DashboardFragment : Fragment() {
    private val viewModel: DashboardViewModel by viewModels()

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        val logoutRequestInProgress = mutableStateOf(false)

        viewModel.logoutStateLiveData.observe(viewLifecycleOwner) { state ->
            when (state) {
                DashboardViewModel.LogoutState.Failed -> {
                    logoutRequestInProgress.value = false
                    Toast.makeText(requireContext(), "Logout failed.", Toast.LENGTH_LONG).show()
                }
                DashboardViewModel.LogoutState.Success -> {
                    logoutRequestInProgress.value = false
                    viewModel.acknowledgeLogoutSuccess()
                    findNavController().navigate(DashboardFragmentDirections.dashboardToLogin())
                }
                DashboardViewModel.LogoutState.Idle -> {
                    logoutRequestInProgress.value = false
                }
                DashboardViewModel.LogoutState.Loading -> {
                    logoutRequestInProgress.value = true
                }
            }
        }

        return ComposeView(requireContext()).apply {
            setContent {
                MdcTheme {
                    Dashboard(
                        token = viewModel.tokenState,
                        userInfo = viewModel.userInfoState,
                        logoutRequestInProgress = logoutRequestInProgress,
                        logoutClick = viewModel::logout
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalUnitApi::class)
@Composable
internal fun Dashboard(
    token: State<Token?>,
    userInfo: State<Map<String, String>>,
    logoutRequestInProgress: State<Boolean>,
    logoutClick: () -> Unit,
) {
    val scrollState = rememberScrollState()
    Column(
        modifier = Modifier
            .verticalScroll(
                state = scrollState,
            )
            .padding(16.dp)
            .fillMaxHeight()
    ) {
        Text(
            text = stringResource(R.string.you_are_logged_in),
            fontSize = TextUnit(20f, TextUnitType.Sp),
            fontWeight = FontWeight.Bold
        )

        Tokens(token.value)

        UserInfo(userInfo.value)

        Button(onClick = logoutClick, enabled = !logoutRequestInProgress.value) {
            Text(text = stringResource(R.string.sign_out))
        }
    }
}

@Composable
fun Tokens(token: Token?) {
    if (token != null) {
        LabeledText(stringResource(R.string.token_type), token.tokenType)
        LabeledText(stringResource(R.string.expires_in), token.expiresIn.toString())
        LabeledText(stringResource(R.string.access_token), token.accessToken)
        LabeledText(stringResource(R.string.refresh_token), token.refreshToken)
        LabeledText(stringResource(R.string.id_token), token.idToken)
        LabeledText(stringResource(R.string.device_secret), token.deviceSecret)
        LabeledText(stringResource(R.string.scope), token.scope)
    }
}

@Composable
fun LabeledText(label: String, value: String?) {
    if (value != null) {
        Text(text = label, fontWeight = FontWeight.Bold)
        Text(text = value)
    }
}

@OptIn(ExperimentalUnitApi::class)
@Composable
fun UserInfo(userInfo: Map<String, String>) {
    if (userInfo.isNotEmpty()) {
        Text(text = stringResource(R.string.claims), fontSize = TextUnit(20f, TextUnitType.Sp), fontWeight = FontWeight.Bold)

        for (entry in userInfo) {
            Claim(entry.key, entry.value)
        }
    }
}

@Composable
fun Claim(label: String, value: String) {
    Text(text = "$label: $value")
}

@Preview
@Composable
fun PreviewEmptyLabeledText() {
    LabeledText(label = "Not showing", value = null)
}

@Preview
@Composable
fun PreviewLabeledText() {
    LabeledText(label = "Example", value = "Value")
}
