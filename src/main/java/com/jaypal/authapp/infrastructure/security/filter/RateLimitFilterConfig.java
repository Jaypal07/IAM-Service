package com.jaypal.authapp.infrastructure.security.filter;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class RateLimitFilterConfig {

    private final RateLimitFilter rateLimitFilter;

    @Bean
    public FilterRegistrationBean<RateLimitFilter> rateLimitFilterRegistration() {
        FilterRegistrationBean<RateLimitFilter> bean = new FilterRegistrationBean<>();
        bean.setFilter(rateLimitFilter);
        bean.setOrder(1); // BEFORE Spring Security
        return bean;
    }
}
