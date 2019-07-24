package com.tbxark.jwt.security.core


import com.tbxark.jwt.security.core.dto.ResponseWrapper
import org.springframework.http.MediaType
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.stereotype.Component
import java.io.Serializable
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
class JwtAccessDeniedHandler : AccessDeniedHandler, Serializable {

    override fun handle(request: HttpServletRequest?, response: HttpServletResponse?, accessDeniedException: AccessDeniedException?) {
        response?.contentType = MediaType.APPLICATION_PROBLEM_JSON_UTF8_VALUE
        response?.status = HttpServletResponse.SC_FORBIDDEN
        response?.writer?.println(body)
    }

    companion object {
        private const val serialVersionUID = 1L
        internal val body = ResponseWrapper.failure<Any>(HttpServletResponse.SC_FORBIDDEN, "Access Denied").toJSON()
    }
}