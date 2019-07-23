package com.tbxark.jwt.security.core.model

import org.springframework.http.HttpStatus

class AuthenticationException(val code: Int = HttpStatus.UNAUTHORIZED.value(), message: String? = null, cause: Throwable? = null) : RuntimeException(message, cause) {
    companion object {
        fun unauthorized(message: String, cause: Throwable? = null): AuthenticationException {
            return AuthenticationException(HttpStatus.UNAUTHORIZED.value(), message, cause)
        }

        fun wrapper(cause: Throwable? = null): AuthenticationException {
            return AuthenticationException(HttpStatus.UNAUTHORIZED.value(), null, cause)
        }
    }

    override val message: String?
        get() = super.message ?: this.cause?.message ?: "Authentication Exception"
}