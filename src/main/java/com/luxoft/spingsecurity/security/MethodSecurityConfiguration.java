package com.luxoft.spingsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

@Configuration
@EnableGlobalMethodSecurity(
        prePostEnabled = true, // Включает поддержку @PreAuthorize и @PostAuthorize
        securedEnabled = true, // Включает поддержку @Secured
        jsr250Enabled = true   // Включает поддержку @RolesAllowed
)
public class MethodSecurityConfiguration {

    @Bean
    public MethodSecurityExpressionHandler defaultMethodSecurityExpressionHandler() {
        return new DefaultMethodSecurityExpressionHandler();
    }
}
