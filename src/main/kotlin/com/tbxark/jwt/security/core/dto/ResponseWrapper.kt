package com.tbxark.jwt.security.core.dto

import com.google.gson.Gson

data class ResponseWrapper<T>(val status: Int, val message: String?, val data: T?, val error: String?) {

    companion object {

        val gson = Gson()

        fun <T> success(data: T): ResponseWrapper<T> {
            return ResponseWrapper(0, null, data, null)
        }

        fun <T> success(): ResponseWrapper<T> {
            return ResponseWrapper(0, null, null, null)
        }

        fun <T> failure(code: Int, message: String): ResponseWrapper<T> {
            return ResponseWrapper(code, null, null, message)
        }
    }

    fun toJSON(): String? {
        return gson.toJson(this)
    }
}