package com.example.forensic.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/logs/upload").hasRole("DEVICE")
                .requestMatchers("/logs/timestamp", "/logs/serverkey").permitAll()
                .requestMatchers("/logs/analyze/**", "/logs/verify/**").hasRole("ADMIN")
                .requestMatchers("/logs/all").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .x509(x509 -> x509
                .subjectPrincipalRegex("CN=(.*?)(?:,|$)")
                .userDetailsService(userDetailsService())
            );

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            // 디바이스 ID 또는 기기 인증서의 Common Name(CN) 기반 UserDetails 반환
            // 여기서는 단순하게 기기 인증서로 인증된 모든 기기에 ROLE_DEVICE 부여
            if (username.startsWith("aegis_device")) {
                return User.withUsername(username)
                        .password("")
                        .roles("DEVICE")
                        .build();
            } else if (username.equals("aegis_admin")) {
                return User.withUsername(username)
                        .password("")
                        .roles("ADMIN")
                        .build();
            }
            // 알 수 없는 기기인 경우 빈 권한 반환
            return User.withUsername(username)
                    .password("")
                    .roles("USER")
                    .build();
        };
    }
}
