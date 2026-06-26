package com.pm.auth.event.payload;

import java.time.Instant;
import java.util.UUID;

public abstract class BaseEvent {

    private final String eventId = UUID.randomUUID().toString();
    private final Instant timestamp = Instant.now();
    private final String eventType;
    private final String userId;

    protected BaseEvent(String eventType, String userId) {
        this.eventType = eventType;
        this.userId = userId;
    }

    public String getEventId()   { return eventId; }
    public Instant getTimestamp() { return timestamp; }
    public String getEventType() { return eventType; }
    public String getUserId()    { return userId; }
}
