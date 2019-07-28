package com.tbxark.jwt.security.core.repository

import com.tbxark.jwt.security.domain.User
import org.springframework.cache.annotation.CacheConfig
import org.springframework.cache.annotation.CachePut
import org.springframework.cache.annotation.Cacheable
import org.springframework.data.jpa.repository.JpaRepository

@CacheConfig(cacheNames=["users"])
interface UserRepository : JpaRepository<User, Long> {


    @CachePut(key = "#p0.username")
    fun save(user: User): User

    @Cacheable(key = "#p0")
    fun findByUsername(username: String): User?
}