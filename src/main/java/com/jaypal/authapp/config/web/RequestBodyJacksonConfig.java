package com.jaypal.authapp.config.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.jaypal.authapp.config.utils.TrimStringDeserializer;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.context.annotation.Bean;


@Configuration
public class RequestBodyJacksonConfig {

    @Bean
    public MappingJackson2HttpMessageConverter trimmingJacksonConverter(
            ObjectMapper objectMapper) {

        ObjectMapper copy = objectMapper.copy();

        SimpleModule module = new SimpleModule();
        module.addDeserializer(String.class, new TrimStringDeserializer());

        copy.registerModule(module);

        return new MappingJackson2HttpMessageConverter(copy);
    }
}

