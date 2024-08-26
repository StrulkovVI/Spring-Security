package com.luxoft.spingsecurity.security;

import com.luxoft.spingsecurity.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    private final UserDetailsService userDetailsService;

    public SecurityConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/h2-console/**");
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .sessionManagement() // по умолчанию - spring Будет хранить сессию на сервере
                .and()
                .authorizeRequests()
                .antMatchers( "/login", "/deny.html", "/logout").permitAll()
                .antMatchers( "/user/whoami").permitAll()
                .antMatchers("/company/**", "/user/**").authenticated()
                .antMatchers( "/info").hasAuthority("ROLE_ANON")
                .antMatchers("/**").denyAll()
                .and()
                .x509()
                .userDetailsService(userDetailsService)
                .and();
                /*.httpBasic()
                .and()
                .formLogin()
                .and()
                .anonymous()
                //.authorities("ROLE_ANON");
                .principal(new UserDetailsAdapter(anonymous()));*/
        //.loginPage("/login")
        //.loginProcessingUrl("/login")
        //.failureUrl("/deny.html")
        //.defaultSuccessUrl("/company", true);
        return http.build();
    }

    private User anonymous() {
        User anonUser = new User();
        anonUser.setId(-1);
        anonUser.setLogin("anon");
        anonUser.setPassword("");
        anonUser.setRoles(Collections.singletonList("ROLE_ANON"));
        return anonUser;
    }
}
