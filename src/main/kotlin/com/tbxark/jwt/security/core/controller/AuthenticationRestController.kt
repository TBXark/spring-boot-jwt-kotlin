package com.tbxark.jwt.security.core.controller

import com.tbxark.jwt.security.core.JwtTokenUtil
import com.tbxark.jwt.security.core.model.AuthenticationException
import com.tbxark.jwt.security.core.model.JwtAuthenticationRequest
import com.tbxark.jwt.security.core.model.JwtAuthenticationResponse
import com.tbxark.jwt.security.core.service.AuthenticationService
import com.tbxark.jwt.security.model.ResponseWrapper
import com.tbxark.jwt.security.model.User
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.web.bind.annotation.*
import javax.servlet.http.HttpServletRequest


@RestController
@RequestMapping("/auth")
class AuthenticationRestController {

    @Autowired
    private lateinit var authenticationService: AuthenticationService

    @Autowired
    private lateinit var jwtTokenUtil: JwtTokenUtil


    @PostMapping("/register")
    @Throws(AuthenticationException::class)
    fun registerAuthenticationToken(@RequestBody authenticationRequest: JwtAuthenticationRequest): ResponseWrapper<User> {
        val user = authenticationService.register(authenticationRequest)
        return ResponseWrapper.success(user)
    }

    @PostMapping("/login")
    @Throws(AuthenticationException::class)
    fun createAuthenticationToken(@RequestBody authenticationRequest: JwtAuthenticationRequest): ResponseWrapper<JwtAuthenticationResponse> {
        val token = authenticationService.login(authenticationRequest)
        return ResponseWrapper.success(token)
    }

    @GetMapping("/refresh")
    @Throws(AuthenticationException::class)
    fun refreshAndGetAuthenticationToken(request: HttpServletRequest): ResponseWrapper<JwtAuthenticationResponse> {
        val tokenRaw = jwtTokenUtil.getTokenFromHttpServletRequest(request)
                ?: throw AuthenticationException.unauthorized("authToken must not be null")
        val token = authenticationService.refresh(tokenRaw)
        return ResponseWrapper.success(token)
    }


}