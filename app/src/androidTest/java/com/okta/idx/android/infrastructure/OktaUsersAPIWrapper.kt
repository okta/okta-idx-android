package com.okta.idx.android.infrastructure

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.okta.idx.android.network.Network
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

object OktaUsersAPIWrapper {
    private val client = OkHttpClient()
    private val objectMapper = ObjectMapper()
    init {
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
    }

    fun createUserWithPassword(
        userEmail: String,
        userPassword: String
    ) {
        val createUserRequest = CreateUserRequest(
            profile = Profile(
                firstName = "Mary",
                lastName = "Jo",
                email = userEmail,
                login = userEmail
            ), credentials = Credentials(
                password = Password(userPassword)
            )
        )
        val requestBody = objectMapper.writeValueAsString(createUserRequest)

        val url = "${Network.baseUrl}/api/v1/users?activate=true"
        val request = Request.Builder()
            .url(url)
            .post(requestBody.toRequestBody("application/json".toMediaType()))
            .header("Authorization", "SSWS ${EndToEndCredentials["/orgConfig/apikey"]}")
            .build()

        client.newCall(request).execute()
    }
}