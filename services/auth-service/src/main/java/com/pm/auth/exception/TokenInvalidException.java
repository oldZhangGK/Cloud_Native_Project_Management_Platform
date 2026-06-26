package com.pm.auth.exception;

public class TokenInvalidException extends RuntimeException {
    public TokenInvalidException() {
        super("Refresh token is invalid");
    }
}
