package com.pm.auth.event.payload;

import com.pm.auth.domain.User;

public class UserRegisteredEvent extends BaseEvent {

    private final String email;
    private final String firstName;
    private final String lastName;

    public UserRegisteredEvent(User user) {
        super("USER_REGISTERED", user.getId().toString());
        this.email = user.getEmail();
        this.firstName = user.getFirstName();
        this.lastName = user.getLastName();
    }

    public String getEmail()     { return email; }
    public String getFirstName() { return firstName; }
    public String getLastName()  { return lastName; }
}
