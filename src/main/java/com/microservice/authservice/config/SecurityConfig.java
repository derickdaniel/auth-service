package com.microservice.authservice.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.microservice.authservice.jwt.AuthTokenFilter;
import com.microservice.authservice.jwt.JWTAccessDeniedHandler;
import com.microservice.authservice.jwt.JwtAuthenticationEntryPoint;
import com.microservice.authservice.jwt.JwtUtils;
import com.microservice.authservice.security.CustomUserDetailsService;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	@Autowired
	private JwtAuthenticationEntryPoint authenticationEntryPoint;
	@Autowired
	private JWTAccessDeniedHandler accessDeniedHandler;
	@Autowired
	private JwtUtils jwtUtils;
	@Autowired
	private CustomUserDetailsService customUserDetailsService;

	@Bean
	public AuthenticationManager authenticationManager(final AuthenticationConfiguration authenticationConfiguration)
			throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		return http.headers().frameOptions().disable().and().csrf().disable().cors().and().authorizeRequests(auth -> {
			auth.anyRequest().permitAll();
		}).formLogin().disable().httpBasic().disable().exceptionHandling().accessDeniedHandler(accessDeniedHandler)
				.authenticationEntryPoint(authenticationEntryPoint).and().sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
				.addFilterBefore(authenticationJwtTokenFilter(jwtUtils, customUserDetailsService),
						UsernamePasswordAuthenticationFilter.class)
				.build();
	}

	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		return (web) -> web.ignoring().antMatchers("/authenticate/signup", "/authenticate/login", "/authenticate/refreshtoken");
	}

	@Bean
	public AuthTokenFilter authenticationJwtTokenFilter(JwtUtils jwtUtils,
			CustomUserDetailsService customUserDetailsService) {
		return new AuthTokenFilter(jwtUtils, customUserDetailsService);
	}
}
