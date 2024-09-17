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
package com.okta.idx.android.dynamic

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import timber.log.Timber

class MainActivity : AppCompatActivity() {
    companion object {
        const val SOCIAL_REDIRECT_ACTION = "SocialRedirect"
        const val EMAIL_REDIRECT_ACTION = "EmailRedirect"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContentView(R.layout.activity_main)
    }

    public override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)

        when (intent.action) {
            SOCIAL_REDIRECT_ACTION -> {
                intent.data?.let {
                    SocialRedirectCoordinator.listener?.invoke(it)
                } ?: run {
                    Timber.d("SocialRedirect intent data missing")
                }
            }
            EMAIL_REDIRECT_ACTION -> {
                intent.data?.let {
                    EmailRedirectCoordinator.listener?.invoke(it, this)
                } ?: run {
                    Timber.d("EmailRedirect intent data missing")
                }
            }
        }
        if (intent?.action == SOCIAL_REDIRECT_ACTION) {
            intent.data?.let {
                SocialRedirectCoordinator.listener?.invoke(it)
            }
        }
    }
}
