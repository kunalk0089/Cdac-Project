package com.agrimedic.agrimedic_backend.config;

import com.agrimedic.agrimedic_backend.security.JwtAuthFilter;
import com.agrimedic.agrimedic_backend.security.UserDetailsServiceImpl;
import com.agrimedic.agrimedic_backend.util.JwtUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    private final JwtUtil jwtUtil;
    private final UserDetailsServiceImpl userDetailsService;

    public SecurityConfig(JwtUtil jwtUtil, UserDetailsServiceImpl userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public JwtAuthFilter jwtAuthFilter() {
        return new JwtAuthFilter(jwtUtil, userDetailsService);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth

                // Public endpoints
                .requestMatchers("/api/auth/**").permitAll()

                // Shop owner endpoints
                .requestMatchers("/api/shop/**").hasRole("SHOPOWNER")

                // Expert/Admin reply endpoint
                .requestMatchers("/api/issues/*/reply").hasAnyRole("EXPERT", "ADMIN")

                // Expert/Admin diagnose endpoint
                .requestMatchers("/api/issues/*/diagnose").hasAnyRole("EXPERT", "ADMIN")

                // Farmer-only endpoints
                .requestMatchers("/api/issues/mine").hasRole("FARMER")

                // Other issue endpoints accessible to all roles
                .requestMatchers("/api/issues/**").hasAnyRole("FARMER", "EXPERT", "ADMIN")

                // Admin-only endpoints
                .requestMatchers("/api/admin/**").hasRole("ADMIN")

                // Everything else requires authentication
                .anyRequest().authenticated()
            );

        // Add JWT filter before the default UsernamePasswordAuthenticationFilter
        http.addFilterBefore(jwtAuthFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
