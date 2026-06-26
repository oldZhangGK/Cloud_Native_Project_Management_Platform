package com.pm.auth.event.payload;

import java.util.UUID;

public class PasswordChangedEvent extends BaseEvent {

    private final String email;

    public PasswordChangedEvent(UUID userId, String email) {
        super("PASSWORD_CHANGED", userId.toString());
        this.email = email;
    }

    public String getEmail() { return email; }
}
