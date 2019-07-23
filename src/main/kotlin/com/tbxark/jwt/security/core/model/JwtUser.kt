package com.tbxark.jwt.security.core.model

import com.fasterxml.jackson.annotation.JsonIgnore
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import java.util.*


class JwtUser(
        @get:JsonIgnore
        val id: Long?,
        val nickname: String?,
        val email: String?,
        private val username: String,
        private val password: String,
        private val authorities: Collection<GrantedAuthority>,
        private val enabled: Boolean,
        @get:JsonIgnore
        val lastPasswordResetDate: Date
) : UserDetails {

    override fun getUsername(): String {
        return username
    }

    @JsonIgnore
    override fun isAccountNonExpired(): Boolean {
        return true
    }

    @JsonIgnore
    override fun isAccountNonLocked(): Boolean {
        return true
    }

    @JsonIgnore
    override fun isCredentialsNonExpired(): Boolean {
        return true
    }

    @JsonIgnore
    override fun getPassword(): String {
        return password
    }

    override fun getAuthorities(): Collection<GrantedAuthority> {
        return authorities
    }

    override fun isEnabled(): Boolean {
        return enabled
    }
}