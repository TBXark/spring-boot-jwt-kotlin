package com.tbxark.jwt.security.core.controller

import com.tbxark.jwt.security.core.dto.AuthenticationException
import com.tbxark.jwt.security.core.dto.ResponseWrapper
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.ResponseBody

@ControllerAdvice
class AuthenticationExceptionController {

    @ExceptionHandler(AccessDeniedException::class)
    @ResponseBody
    fun handleAccessDeniedException(e: AccessDeniedException): ResponseWrapper<Any> = ResponseWrapper.failure(HttpStatus.UNAUTHORIZED.value(), e.message
            ?: "access Denied")

    @ExceptionHandler(AuthenticationException::class)
    @ResponseBody
    fun handleAuthenticationException(e: AuthenticationException): ResponseWrapper<Any> = ResponseWrapper.failure(HttpStatus.UNAUTHORIZED.value(), e.message
            ?: "unauthorized")
}