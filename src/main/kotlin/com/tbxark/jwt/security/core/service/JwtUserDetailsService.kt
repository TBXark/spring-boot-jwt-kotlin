package com.tbxark.jwt.security.core.service

import com.tbxark.jwt.security.core.JwtUserFactory
import com.tbxark.jwt.security.core.repository.UserRepository
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service

@Service
class JwtUserDetailsService : UserDetailsService {

    @Autowired
    private lateinit var userRepository: UserRepository

    override fun loadUserByUsername(username: String?): UserDetails {
        val name = username ?: throw UsernameNotFoundException("Username can not be empty")
        val user = userRepository.findByUsername(name)
                ?: throw UsernameNotFoundException("No user found with username $name")
        return JwtUserFactory.create(user)
    }
}