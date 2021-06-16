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
package com.okta.idx.android.cucumber.definitions

import android.app.Application
import android.content.Intent
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import com.okta.idx.android.infrastructure.EndToEndCredentials
import com.okta.idx.android.infrastructure.espresso.clickButtonWithText
import com.okta.idx.android.infrastructure.espresso.fillInEditText
import com.okta.idx.android.infrastructure.espresso.scrollToToBottom
import com.okta.idx.android.infrastructure.espresso.waitForElementWithText
import io.cucumber.java.Before
import io.cucumber.java.en.And
import timber.log.Timber

internal class SocialDefinitions {
    @Before("@logOutOfFacebook", order = 0)
    fun logOutOfFacebook() {
        // Open browser to facebook.com
        val application = ApplicationProvider.getApplicationContext<Application>()
        val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse("https://facebook.com"))
        browserIntent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
        application.startActivity(browserIntent)

        try {
            clickButtonWithText("Accept & continue")
            clickButtonWithText("No thanks")
        } catch (e: Throwable) {
            Timber.e(e, "Error Calling accept and continue")
        }

        try {
            // If logged in ("Main Menu") text available
            waitForElementWithText("Main Menu")
            clickButtonWithText("Main Menu")
            scrollToToBottom()
            waitForElementWithText("Log Out")
            clickButtonWithText("Log Out")
            waitForElementWithText("Create New Account")
        } catch (e: Throwable) {
            Timber.e(e, "Error Logging out of facebook. This is expected if not logged in.")
        }
    }

    @And("^logs in to Facebook$") fun logs_in_to_facebook() {
        fillInEditText("m_login_email", EndToEndCredentials["/cucumber/facebookEmail"])
        fillInEditText("m_login_password", EndToEndCredentials["/cucumber/facebookPassword"])
        clickButtonWithText("Log In")
    }
}
