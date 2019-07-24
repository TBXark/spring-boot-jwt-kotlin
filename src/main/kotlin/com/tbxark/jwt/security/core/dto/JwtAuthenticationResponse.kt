package com.tbxark.jwt.security.core.dto

import java.io.Serializable

data class JwtAuthenticationResponse(val token: String) : Serializable {
    companion object {
        private const val serialVersionUID = 1250166508152483573L
    }
}