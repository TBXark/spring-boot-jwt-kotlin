package com.tbxark.jwt.security.core.controller

import com.tbxark.jwt.security.core.JwtTokenUtil
import com.tbxark.jwt.security.core.dto.AuthenticationException
import com.tbxark.jwt.security.core.dto.JwtAuthenticationRequest
import com.tbxark.jwt.security.core.dto.JwtAuthenticationResponse
import com.tbxark.jwt.security.core.service.AuthenticationService
import com.tbxark.jwt.security.core.dto.ResponseWrapper
import com.tbxark.jwt.security.domain.User
import com.tbxark.jwt.security.dto.UserDTO
import com.tbxark.jwt.security.utils.DTOFactory
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
    fun registerAuthenticationToken(@RequestBody authenticationRequest: JwtAuthenticationRequest): ResponseWrapper<UserDTO> {
        val user = authenticationService.register(authenticationRequest)
        return ResponseWrapper.success(DTOFactory.create(user))
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