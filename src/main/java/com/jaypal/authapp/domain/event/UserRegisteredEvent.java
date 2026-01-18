package com.jaypal.authapp.domain.event;

import java.util.UUID;

public record UserRegisteredEvent(UUID userId) {}
