package com.pm.auth.exception;

public class AccountDisabledException extends RuntimeException {
    public AccountDisabledException() {
        super("This account has been deactivated");
    }
}
