package com.pm.auth.exception;

public class TokenExpiredException extends RuntimeException {
    public TokenExpiredException() {
        super("Refresh token has expired");
    }
}
