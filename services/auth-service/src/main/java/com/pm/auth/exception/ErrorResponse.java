package com.pm.auth.exception;

import java.time.Instant;

public record ErrorResponse(
    int status,
    String code,
    String message,
    Instant timestamp,
    String path
) {}
