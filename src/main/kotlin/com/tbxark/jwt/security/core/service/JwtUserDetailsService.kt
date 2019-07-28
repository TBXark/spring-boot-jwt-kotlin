package com.tbxark.jwt.security.core.service

import com.tbxark.jwt.security.core.JwtTokenUtil
import com.tbxark.jwt.security.core.JwtUserFactory
import com.tbxark.jwt.security.core.dto.AuthenticationException
import com.tbxark.jwt.security.core.dto.JwtAuthenticationRequest
import com.tbxark.jwt.security.core.dto.JwtAuthenticationResponse
import com.tbxark.jwt.security.core.dto.JwtUser
import com.tbxark.jwt.security.core.repository.AuthorityRepository
import com.tbxark.jwt.security.core.repository.UserRepository
import com.tbxark.jwt.security.domain.Authority
import com.tbxark.jwt.security.domain.AuthorityName
import com.tbxark.jwt.security.domain.User
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.DisabledException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.util.*
import java.util.logging.Logger

@Service
class JwtUserDetailsService : UserDetailsService {

    @Autowired
    private lateinit var userRepository: UserRepository

    @Autowired
    private lateinit var authenticationManager: AuthenticationManager

    @Autowired
    private lateinit var jwtTokenUtil: JwtTokenUtil

    @Autowired
    private lateinit var authorityRepository: AuthorityRepository

    private val logger = Logger.getLogger(JwtUserDetailsService::class.toString())


    @Throws(AuthenticationException::class)
    private fun authenticate(username: String, password: String) {
        Objects.requireNonNull(username)
        Objects.requireNonNull(password)
        try {
            authenticationManager.authenticate(UsernamePasswordAuthenticationToken(username, password))
        } catch (e: DisabledException) {
            logger.warning("DisabledException ${e.message}\n${e.stackTrace}")
            throw AuthenticationException.unauthorized("User is disabled!", e)
        } catch (e: BadCredentialsException) {
            logger.warning("BadCredentialsException ${e.message}\n${e.stackTrace}")
            throw AuthenticationException.unauthorized("Bad credentials!", e)
        }

    }

    fun login(request: JwtAuthenticationRequest): JwtAuthenticationResponse {
        authenticate(request.username, request.password)
        val userDetails = loadUserByUsername(request.username)
        val token = jwtTokenUtil.generateToken(userDetails)
        return JwtAuthenticationResponse(token)
    }

    @Throws(AuthenticationException::class)
    @Transactional
    fun register(request: JwtAuthenticationRequest): User {
        if (userRepository.findByUsername(request.username) != null) {
            throw AuthenticationException(HttpStatus.BAD_REQUEST.value(), "Username exist", null)
        }
        var authority = authorityRepository.findByName(AuthorityName.ROLE_USER)
                ?: Authority(null, AuthorityName.ROLE_USER, null)
        if (authority.id == null) {
            authority = authorityRepository.save(authority)
        }
        var user = User(null, request.username, BCryptPasswordEncoder().encode(request.password), request.username, null, true, Date(), listOf(authority))
        user = userRepository.save(user=user)
        return user
    }

    @Throws(AuthenticationException::class)
    fun refresh(token: String): JwtAuthenticationResponse {
        try {
            val username = jwtTokenUtil.getUsernameFromToken(token)
            val user = loadUserByUsername(username) as JwtUser

            if (jwtTokenUtil.canTokenBeRefreshed(token, user.lastPasswordResetDate)) {
                val refreshedToken = jwtTokenUtil.refreshToken(token)
                return JwtAuthenticationResponse(refreshedToken)
            } else {
                throw AuthenticationException.unauthorized("Can not refresh token")
            }
        } catch (e: Exception) {
            throw AuthenticationException.wrapper(e)
        }
    }

    override fun loadUserByUsername(username: String?): UserDetails {
        val name = username ?: throw UsernameNotFoundException("Username can not be empty")
        val user = userRepository.findByUsername(name)
                ?: throw UsernameNotFoundException("No user found with username $name")
        return JwtUserFactory.create(user)
    }
}