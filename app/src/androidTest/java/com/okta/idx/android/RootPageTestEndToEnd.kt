package com.okta.idx.android

import androidx.lifecycle.Lifecycle
import androidx.test.espresso.Espresso
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.assertion.ViewAssertions
import androidx.test.espresso.matcher.ViewMatchers
import androidx.test.ext.junit.rules.ActivityScenarioRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.hamcrest.CoreMatchers
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RootPageTestEndToEnd {
    @get:Rule
    val activityRule = ActivityScenarioRule(MainActivity::class.java)

    //Mary visits the Root View WITHOUT an authentcation session (no tokens)
    @Test
    fun scenario_0_1_1() {
        activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        onView(
            CoreMatchers.allOf(
                ViewMatchers.withId(R.id.login_button)
            )
        ).check(
            ViewAssertions.matches(ViewMatchers.isDisplayed())
        )
        onView(
            CoreMatchers.allOf(
                ViewMatchers.withId(R.id.self_service_registration_button)
            )
        ).check(
            ViewAssertions.matches(ViewMatchers.isDisplayed())
        )
    }
}