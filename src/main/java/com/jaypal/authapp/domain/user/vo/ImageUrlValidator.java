package com.jaypal.authapp.domain.user.vo;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Set;

public final class ImageUrlValidator {

    private static final Set<String> ALLOWED_SCHEMES = Set.of("https", "http");

    private ImageUrlValidator() {}

    public static void validate(String imageUrl) {
        if (imageUrl == null || imageUrl.isBlank()) {
            return; // image is optional
        }

        URI uri;
        try {
            uri = new URI(imageUrl.trim());
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid image URL");
        }

        String scheme = uri.getScheme();
        if (scheme == null || !ALLOWED_SCHEMES.contains(scheme.toLowerCase())) {
            throw new IllegalArgumentException("Invalid image URL scheme");
        }

        if (uri.getHost() == null) {
            throw new IllegalArgumentException("Invalid image URL host");
        }

        if (imageUrl.contains("\n") || imageUrl.contains("\r")) {
            throw new IllegalArgumentException("Invalid image URL");
        }
    }
}
