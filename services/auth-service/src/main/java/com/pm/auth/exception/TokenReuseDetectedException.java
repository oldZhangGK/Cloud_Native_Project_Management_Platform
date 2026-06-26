package com.pm.auth.exception;

public class TokenReuseDetectedException extends RuntimeException {
    public TokenReuseDetectedException() {
        super("Refresh token reuse detected — all sessions have been invalidated");
    }
}
