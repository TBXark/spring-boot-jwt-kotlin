package com.tbxark.jwt.security.core.model

import java.io.Serializable

data class JwtAuthenticationRequest(val username: String, val password: String) : Serializable {
    companion object {
        private const val serialVersionUID = 1L
    }
}