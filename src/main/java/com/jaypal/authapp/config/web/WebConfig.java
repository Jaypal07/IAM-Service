package com.jaypal.authapp.config.web;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;

import java.util.List;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final MappingJackson2HttpMessageConverter trimmingJacksonConverter;

    public WebConfig(MappingJackson2HttpMessageConverter trimmingJacksonConverter) {
        this.trimmingJacksonConverter = trimmingJacksonConverter;
    }

    @Override
    public void extendMessageConverters(List<HttpMessageConverter<?>> converters) {
        converters.addFirst(trimmingJacksonConverter);
    }
}

