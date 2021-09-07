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
package com.okta.idx.android.network

import com.okta.idx.android.dynamic.BuildConfig
import okhttp3.CookieJar
import okhttp3.OkHttpClient
import java.util.concurrent.atomic.AtomicReference

object Network {
    private val clientConfiguratorReference = AtomicReference<OkHttpConfigurator?>()

    const val baseUrl: String = BuildConfig.ISSUER

    fun okHttpClient(): OkHttpClient {
        val builder = OkHttpClient.Builder()
        builder.cookieJar(CookieJar.NO_COOKIES)
        clientConfiguratorReference.get()?.configure(builder)

        val client = builder.build()
        clientConfiguratorReference.get()?.built(client)
        return client
    }

    fun setConfigurator(configurator: OkHttpConfigurator?) {
        clientConfiguratorReference.set(configurator)
    }
}