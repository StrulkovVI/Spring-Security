package com.luxoft.spingsecurity.security;

import com.luxoft.spingsecurity.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionVoter;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

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
                .csrf().disable()
                .sessionManagement()
                .and()
                .authorizeRequests()
                .antMatchers("/login", "/deny.html", "/logout").permitAll()
                .antMatchers("/user/whoami").permitAll()
                .antMatchers("/company/**", "/user/**").authenticated()
                .antMatchers("/info").hasAuthority("ROLE_ANON")
                .anyRequest().denyAll()
                .and()
                .httpBasic()
                .and()
                .formLogin()
                .and()
                .anonymous()
                .principal(new UserDetailsAdapter(anonymous()));
        return http.build();
    }

    /*@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .sessionManagement() // по умолчанию - spring Будет хранить сессию на сервере
                .and()
                .authorizeRequests()
                .accessDecisionManager(accessAffirmativeBased())
                .antMatchers( "/login", "/deny.html", "/logout").permitAll()
                .antMatchers( "/user/whoami").permitAll()
                .antMatchers("/company/**", "/user/**").authenticated()
                .antMatchers( "/info").hasAuthority("ROLE_ANON")
                .antMatchers("/**").denyAll()
                *//*.and()
                .x509()
                .userDetailsService(userDetailsService)*//*
                .and()
                .httpBasic()
                .and()
                .formLogin()
                .and()
                .anonymous()
                //.authorities("ROLE_ANON");
                .principal(new UserDetailsAdapter(anonymous()));
        //.loginPage("/login")
        //.loginProcessingUrl("/login")
        //.failureUrl("/deny.html")
        //.defaultSuccessUrl("/company", true);
        return http.build();
    }*/

    private User anonymous() {
        User anonUser = new User();
        anonUser.setId(-1);
        anonUser.setLogin("anon");
        anonUser.setPassword("");
        anonUser.setRoles(Collections.singletonList("ROLE_ANON"));
        return anonUser;
    }

    private AccessDecisionVoter<?> createCustomVoter() {
        return new AccessDecisionVoter<>() {
            @Override
            public boolean supports(ConfigAttribute configAttribute) {
                return true;
            }

            @Override
            public boolean supports(Class<?> aClass) {
                return true;
            }

            @Override
            public int vote(Authentication a, Object o, Collection<ConfigAttribute> c) {
                //some custom logic
                return -1;
            }
        };
    }

    private List<AccessDecisionVoter<?>> voters() {
        return Arrays.asList(
                new RoleVoter(),
                new AuthenticatedVoter(),
                new WebExpressionVoter(),
                createCustomVoter()
        );
    }

    private AccessDecisionManager accessUnanimousBased() {
        return new UnanimousBased(voters());
    }
    private AccessDecisionManager accessAffirmativeBased() {
        return new AffirmativeBased(voters());
    }

}
