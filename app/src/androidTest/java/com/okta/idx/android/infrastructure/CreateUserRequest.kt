package com.okta.idx.android.infrastructure

import com.fasterxml.jackson.annotation.JsonProperty

data class CreateUserRequest(
    @JsonProperty("profile")
    val profile: Profile,
    @JsonProperty("credentials")
    val credentials: Credentials
)

data class Profile(
    @JsonProperty("firstName")
    val firstName: String,
    @JsonProperty("lastName")
    val lastName: String,
    @JsonProperty("email")
    val email: String,
    @JsonProperty("login")
    val login: String
)

data class Credentials(
    @JsonProperty("password")
    val password: Password
)

data class Password(
    @JsonProperty("value")
    val value: String
)