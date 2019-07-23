package com.tbxark.jwt.security.core

import com.tbxark.jwt.security.model.ResponseWrapper
import org.springframework.http.MediaType
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.stereotype.Component
import java.io.IOException
import java.io.Serializable
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
class JwtAuthenticationEntryPoint : AuthenticationEntryPoint, Serializable {

    @Throws(IOException::class)
    override fun commence(request: HttpServletRequest,
                          response: HttpServletResponse,
                          authException: AuthenticationException) {
        // This is invoked when user tries to access a secured REST resource without supplying any credentials
        // We should just send a 401 Unauthorized response because there is no 'login page' to redirect to
        response.contentType = MediaType.APPLICATION_PROBLEM_JSON_UTF8_VALUE
        response.status = HttpServletResponse.SC_UNAUTHORIZED
        response.writer.println(body)
    }

    companion object {
        private const val serialVersionUID = 1L
        internal val body = ResponseWrapper.failure<Any>(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized").toJSON()
    }
}