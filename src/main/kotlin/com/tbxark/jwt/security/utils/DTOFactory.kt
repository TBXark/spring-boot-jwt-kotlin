package com.tbxark.jwt.security.utils

import org.modelmapper.ModelMapper

object DTOFactory {
    inline fun <SRC, reified DTO> create(src: SRC, destinationType: Class<DTO> = DTO::class.java): DTO {
        return ModelMapper().map(src, destinationType)
    }
}