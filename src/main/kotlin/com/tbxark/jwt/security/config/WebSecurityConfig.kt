package com.tbxark.jwt.security.config

import com.tbxark.jwt.security.core.JwtAccessDeniedHandler
import com.tbxark.jwt.security.core.JwtAuthenticationEntryPoint
import com.tbxark.jwt.security.core.JwtAuthorizationTokenFilter
import com.tbxark.jwt.security.core.service.JwtUserDetailsService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
class WebSecurityConfig : WebSecurityConfigurerAdapter() {

    @Autowired
    private lateinit var jwtUserDetailsService: JwtUserDetailsService


    @Bean
    fun accessDeniedHandler(): JwtAccessDeniedHandler {
        return JwtAccessDeniedHandler()
    }

    @Bean
    fun unauthorizedHandler(): JwtAuthenticationEntryPoint {
        return JwtAuthenticationEntryPoint()
    }

    @Bean
    fun authenticationTokenFilter(): JwtAuthorizationTokenFilter {
        return JwtAuthorizationTokenFilter()
    }

    @Bean
    fun passwordEncoderBean(): PasswordEncoder {
        return BCryptPasswordEncoder()
    }

    @Bean
    @Throws(Exception::class)
    override fun authenticationManagerBean(): AuthenticationManager {
        return super.authenticationManagerBean()
    }

    @Throws(Exception::class)
    override fun configure(httpSecurity: HttpSecurity) {
        httpSecurity
                // we don't need CSRF because our token is invulnerable
                .csrf().disable()
                // don't create session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .authorizeRequests()
                .anyRequest().authenticated()

        httpSecurity
                .addFilterBefore(authenticationTokenFilter(), UsernamePasswordAuthenticationFilter::class.java)

        // disable page caching
        httpSecurity
                .headers()
                .cacheControl()


        httpSecurity.exceptionHandling()
                .authenticationEntryPoint(unauthorizedHandler())
                .accessDeniedHandler(accessDeniedHandler())

    }

    @Throws(Exception::class)
    override fun configure(web: WebSecurity) {
        // AuthenticationTokenFilter will ignore the below paths

        web
                .ignoring()
                .antMatchers(
                        "/auth/**"
                )
                .and()
                .ignoring()
                .antMatchers(
                        HttpMethod.GET,
                        "/",
                        "/*.html",
                        "/favicon.ico",
                        "/**/*.html",
                        "/**/*.css",
                        "/**/*.js"
                )

    }

    override fun configure(auth: AuthenticationManagerBuilder?) {
        auth?.userDetailsService(jwtUserDetailsService)?.passwordEncoder(passwordEncoderBean())
    }
}