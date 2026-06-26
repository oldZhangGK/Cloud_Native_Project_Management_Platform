package com.pm.auth.event;

import com.pm.auth.domain.User;
import com.pm.auth.event.payload.PasswordChangedEvent;
import com.pm.auth.event.payload.UserRegisteredEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@RequiredArgsConstructor
@Slf4j
public class UserEventPublisher {

    private final KafkaTemplate<String, Object> kafkaTemplate;

    @Value("${app.kafka.topics.user-events}")
    private String userEventsTopic;

    public void publishUserRegistered(User user) {
        UserRegisteredEvent event = new UserRegisteredEvent(user);
        kafkaTemplate.send(userEventsTopic, user.getId().toString(), event);
        log.debug("Published USER_REGISTERED for userId={}", user.getId());
    }

    public void publishPasswordChanged(UUID userId, String email) {
        PasswordChangedEvent event = new PasswordChangedEvent(userId, email);
        kafkaTemplate.send(userEventsTopic, userId.toString(), event);
        log.debug("Published PASSWORD_CHANGED for userId={}", userId);
    }
}
