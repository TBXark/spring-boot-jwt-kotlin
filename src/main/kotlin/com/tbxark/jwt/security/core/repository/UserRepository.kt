package com.tbxark.jwt.security.core.repository

import com.tbxark.jwt.security.model.User
import org.springframework.data.jpa.repository.JpaRepository

interface UserRepository : JpaRepository<User, Long> {
    fun findByUsername(username: String): User?
}