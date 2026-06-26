package com.pm.auth.service;

import com.pm.auth.domain.Role;
import com.pm.auth.domain.RoleName;
import com.pm.auth.domain.User;
import com.pm.auth.dto.request.UpdateProfileRequest;
import com.pm.auth.dto.response.UserResponse;
import com.pm.auth.repository.RoleRepository;
import com.pm.auth.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    @Transactional(readOnly = true)
    public UserResponse getUser(UUID userId) {
        return UserResponse.from(findOrThrow(userId));
    }

    @Transactional
    public UserResponse updateProfile(UUID userId, UpdateProfileRequest request) {
        User user = findOrThrow(userId);
        user.setFirstName(request.firstName().trim());
        user.setLastName(request.lastName().trim());
        return UserResponse.from(userRepository.save(user));
    }

    @Transactional(readOnly = true)
    public Page<UserResponse> listUsers(Pageable pageable) {
        return userRepository.findAll(pageable).map(UserResponse::from);
    }

    @Transactional(readOnly = true)
    public UserResponse getUserById(UUID userId) {
        return UserResponse.from(findOrThrow(userId));
    }

    @Transactional
    public UserResponse assignRoles(UUID userId, Set<RoleName> roleNames) {
        User user = findOrThrow(userId);
        Set<Role> roles = roleRepository.findAllByNameIn(roleNames);
        user.setRoles(roles);
        return UserResponse.from(userRepository.save(user));
    }

    @Transactional
    public UserResponse deactivateUser(UUID userId) {
        User user = findOrThrow(userId);
        user.setActive(false);
        return UserResponse.from(userRepository.save(user));
    }

    private User findOrThrow(UUID userId) {
        return userRepository.findById(userId)
            .orElseThrow(() -> new EntityNotFoundException("User not found: " + userId));
    }
}
