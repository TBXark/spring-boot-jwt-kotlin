package com.tbxark.jwt.security.config

import org.springframework.cache.CacheManager
import org.springframework.cache.annotation.CachingConfigurerSupport
import org.springframework.cache.interceptor.KeyGenerator
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.redis.cache.RedisCacheManager
import org.springframework.data.redis.connection.RedisConnectionFactory
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer

import com.fasterxml.jackson.annotation.JsonAutoDetect
import com.fasterxml.jackson.annotation.PropertyAccessor
import com.fasterxml.jackson.databind.ObjectMapper
import com.tbxark.jwt.security.utils.GsonRedisSerializer
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.data.redis.RedisProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.cache.annotation.EnableCaching
import org.springframework.data.redis.core.RedisOperations
import org.springframework.data.redis.serializer.StringRedisSerializer


@EnableCaching
@Configuration
@ConditionalOnClass(RedisOperations::class)
@EnableConfigurationProperties(RedisProperties::class)
open class RedisConfig : CachingConfigurerSupport() {

    @Bean(name = arrayOf("redisTemplate"))
    @ConditionalOnMissingBean(name = ["redisTemplate"])
    open fun redisTemplate(redisConnectionFactory: RedisConnectionFactory): RedisTemplate<Any, Any> {

        var template = RedisTemplate<Any, Any>()

        val fastJsonRedisSerializer = GsonRedisSerializer(Any::class.java)

        template.valueSerializer = fastJsonRedisSerializer
        template.hashValueSerializer = fastJsonRedisSerializer

        template.keySerializer = StringRedisSerializer()
        template.hashKeySerializer = StringRedisSerializer()

        template.setConnectionFactory(redisConnectionFactory)
        return template
    }

    //缓存管理器
    @Bean
    open fun cacheManager(redisConnectionFactory: RedisConnectionFactory): CacheManager {
        val builder = RedisCacheManager
                .RedisCacheManagerBuilder
                .fromConnectionFactory(redisConnectionFactory)
        return builder.build()
    }

}