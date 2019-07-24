package com.tbxark.jwt.security.core.repository


import com.tbxark.jwt.security.domain.Authority
import com.tbxark.jwt.security.domain.AuthorityName
import org.springframework.data.jpa.repository.JpaRepository

interface AuthorityRepository : JpaRepository<Authority, Long> {
    fun findByName(name: AuthorityName): Authority?
}