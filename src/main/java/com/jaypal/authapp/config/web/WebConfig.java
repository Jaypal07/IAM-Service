package com.jaypal.authapp.config.web;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.ByteArrayHttpMessageConverter;
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
        // Ensure custom Jackson converter is added AFTER ByteArrayHttpMessageConverter
        // to prevent byte[] responses (like OpenAPI cache) from being Base64 encoded
        int position = 0;
        for (int i = 0; i < converters.size(); i++) {
            if (converters.get(i) instanceof ByteArrayHttpMessageConverter) {
                position = i + 1;
                break;
            }
        }
        converters.add(position, trimmingJacksonConverter);
    }
}
