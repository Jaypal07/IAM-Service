package com.jaypal.authapp.config.properties;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.net.MalformedURLException;
import java.net.URL;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "app.frontend")
public class FrontendProperties {

    private String baseUrl;
    private String successRedirect;
    private String failureRedirect;

    @PostConstruct
    public void validate() {
        validateUrl("baseUrl", baseUrl, true);
        validateUrl("successRedirect", successRedirect, false);
        validateUrl("failureRedirect", failureRedirect, false);
    }

    private void validateUrl(String name, String url, boolean required) {
        if (url == null || url.isBlank()) {
            if (required) {
                throw new IllegalStateException(
                        String.format("Frontend property '%s' is required but not configured", name));
            }
            return;
        }

        try {
            new URL(url);
        } catch (MalformedURLException ex) {
            throw new IllegalStateException(
                    String.format("Frontend property '%s' is not a valid URL: %s", name, url), ex);
        }
    }
}