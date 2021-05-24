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
package com.okta.idx.android

import androidx.lifecycle.Lifecycle
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.ext.junit.rules.ActivityScenarioRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.okta.idx.android.infrastructure.espresso.waitForElement
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class BasicLoginWithPasswordMockFreeTest {

    companion object {
        private const val FORGOT_PASSWORD_BUTTON = "com.okta.idx.android:id/forgot_password_button"
        private const val ERROR_TEXT_VIEW = "com.okta.idx.android:id/error_text_view"
        private const val USERNAME_EDIT_TEXT = "com.okta.idx.android:id/username_edit_text"
    }

    @get:Rule val activityRule = ActivityScenarioRule(MainActivity::class.java)

    @Test fun scenario_1_1_2_Mary_doesn_t_know_her_username() {
        activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        onView(withId(R.id.login_button)).perform(click())
        waitForElement(USERNAME_EDIT_TEXT)

        onView(withId(R.id.username_edit_text)).perform(ViewActions.replaceText("mary@unknown.com"))
        onView(withId(R.id.password_edit_text)).perform(ViewActions.replaceText("superSecret"))
        onView(withId(R.id.submit_button)).perform(click())

        waitForElement(ERROR_TEXT_VIEW)
        onView(withId(R.id.error_text_view)).check(matches(ViewMatchers.withText("You do not have permission to perform the requested action.")))
    }

    @Test fun scenario_1_1_8_Mary_clicks_on_the_forgot_password_link() {
        activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        onView(withId(R.id.login_button)).perform(click())

        waitForElement(FORGOT_PASSWORD_BUTTON)
        onView(withId(R.id.forgot_password_button)).perform(click())

        onView(withId(R.id.username_edit_text)).check(matches(isDisplayed()))
        onView(withId(R.id.forgot_password_button)).check(matches(isDisplayed()))
    }
}
