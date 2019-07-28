package com.tbxark.jwt.security.utils
import com.google.gson.Gson
import org.springframework.data.redis.serializer.RedisSerializer
import java.nio.charset.Charset

class GsonRedisSerializer<T>(private val clazz: Class<T>):  RedisSerializer<T> {


    override fun serialize(t: T?): ByteArray? {
        if (t == null) return null
        return gson.toJson(t).toByteArray(DEFAULT_CHARSET)
    }

    override fun deserialize(bytes: ByteArray?): T? {
        if (bytes == null || bytes.isEmpty()) return null
        val str = String(bytes, DEFAULT_CHARSET)
        return gson.fromJson(str, clazz)

    }

    companion object {
        private val gson = Gson()
        private val DEFAULT_CHARSET = Charset.forName("UTF-8")
    }
}