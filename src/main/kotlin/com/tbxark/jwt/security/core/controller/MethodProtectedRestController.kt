package com.tbxark.jwt.security.core.controller

import com.tbxark.jwt.security.model.ResponseWrapper
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class MethodProtectedRestController {

    /**
     * This is an example of some different kinds of granular restriction for endpoints. You can use the built-in SPEL expressions
     * in @PreAuthorize such as 'hasRole()' to determine if a user has access. Remember that the hasRole expression assumes a
     * 'ROLE_' prefix on all role names. So 'ADMIN' here is actually stored as 'ROLE_ADMIN' in database!
     */

    @GetMapping("/protected")
    @PreAuthorize("hasRole('ADMIN')")
    fun protectedGreeting(): ResponseWrapper<String> = ResponseWrapper.success("Greetings from admin protected method!")

}