package com.pm.auth.exception;

public class PasswordResetException extends RuntimeException {

    private final String code;

    public PasswordResetException(String code, String message) {
        super(message);
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}
