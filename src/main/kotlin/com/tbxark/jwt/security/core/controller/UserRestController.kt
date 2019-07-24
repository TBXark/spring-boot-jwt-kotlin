package com.tbxark.jwt.security.core.controller

import com.tbxark.jwt.security.core.JwtTokenUtil
import com.tbxark.jwt.security.core.dto.AuthenticationException
import com.tbxark.jwt.security.core.dto.JwtUser
import com.tbxark.jwt.security.core.dto.ResponseWrapper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import javax.servlet.http.HttpServletRequest


@RestController
class UserRestController {


    @Autowired
    private lateinit var jwtTokenUtil: JwtTokenUtil

    @Autowired
    @Qualifier("jwtUserDetailsService")
    private lateinit var userDetailsService: UserDetailsService

    @GetMapping("/user")
    @Throws(AuthenticationException::class)
    fun getAuthenticatedUser(request: HttpServletRequest): ResponseWrapper<JwtUser> {
        val token = jwtTokenUtil.getTokenFromHttpServletRequest(request)
                ?: throw AuthenticationException(message = "authToken must not be null")
        val username = jwtTokenUtil.getUsernameFromToken(token)
        return ResponseWrapper.success(userDetailsService.loadUserByUsername(username) as JwtUser)
    }

}