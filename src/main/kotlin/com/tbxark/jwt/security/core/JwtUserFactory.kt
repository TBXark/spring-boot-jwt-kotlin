package com.tbxark.jwt.security.core

import com.tbxark.jwt.security.core.dto.JwtUser
import com.tbxark.jwt.security.domain.Authority
import com.tbxark.jwt.security.domain.User
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import kotlin.streams.toList


object JwtUserFactory {

    fun create(user: User): JwtUser {
        return JwtUser(
                user.id,
                user.nickname,
                user.email,
                user.username,
                user.password,
                mapToGrantedAuthorities(user.authorities ?: listOf()),
                user.enabled,
                user.lastPasswordResetDate
        )
    }

    private fun mapToGrantedAuthorities(authorities: List<Authority>): List<GrantedAuthority> {
        return authorities.stream()
                .map { (_, name) -> SimpleGrantedAuthority(name.name) }
                .toList()
    }
}