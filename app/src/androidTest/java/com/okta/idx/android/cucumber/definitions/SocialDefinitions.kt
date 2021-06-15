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

import com.okta.idx.android.infrastructure.EndToEndCredentials
import com.okta.idx.android.infrastructure.espresso.clickButtonWithText
import com.okta.idx.android.infrastructure.espresso.fillInEditText
import io.cucumber.java.Before
import io.cucumber.java.en.And

internal class SocialDefinitions {
    @Before("@logOutOfFacebook")
    fun logOutOfFacebook() {
        // TODO: Log out of facebook before test starts.
    }

    @And("^logs in to Facebook$") fun logs_in_to_facebook() {
        fillInEditText("m_login_email", EndToEndCredentials["/cucumber/facebookEmail"])
        fillInEditText("m_login_password", EndToEndCredentials["/cucumber/facebookPassword"])
        clickButtonWithText("Log In")
    }
}
