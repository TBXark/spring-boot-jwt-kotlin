package com.tbxark.jwt.security.dto

import javax.persistence.Embeddable

@Embeddable
data class UserDTO(var id: Long, var username: String, var nickname: String?, var email: String?)
