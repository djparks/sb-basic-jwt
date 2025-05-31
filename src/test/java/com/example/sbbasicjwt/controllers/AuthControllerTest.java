package com.example.sbbasicjwt.controllers;

import com.example.sbbasicjwt.model.ERole;
import com.example.sbbasicjwt.model.Role;
import com.example.sbbasicjwt.model.User;
import com.example.sbbasicjwt.payload.request.LoginRequest;
import com.example.sbbasicjwt.payload.request.SignupRequest;
import com.example.sbbasicjwt.repository.RoleRepository;
import com.example.sbbasicjwt.repository.UserRepository;
import com.example.sbbasicjwt.security.jwt.JwtUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtils jwtUtils;

    private final String testUsername = "testuser";
    private final String testEmail = "test@example.com";
    private final String testPassword = "password123";

    @BeforeEach
    public void setup() {
        // Clean up test user if exists
        userRepository.findByUsername(testUsername).ifPresent(userRepository::delete);

        // Delete any users with test email (by first finding users with matching username)
        userRepository.findAll().stream()
            .filter(user -> testEmail.equals(user.getEmail()))
            .forEach(userRepository::delete);

        // Ensure roles exist
        if (!roleRepository.findByName(ERole.ROLE_USER).isPresent()) {
            roleRepository.save(new Role(ERole.ROLE_USER));
        }
        if (!roleRepository.findByName(ERole.ROLE_MODERATOR).isPresent()) {
            roleRepository.save(new Role(ERole.ROLE_MODERATOR));
        }
        if (!roleRepository.findByName(ERole.ROLE_ADMIN).isPresent()) {
            roleRepository.save(new Role(ERole.ROLE_ADMIN));
        }
    }

    @Test
    @org.springframework.transaction.annotation.Transactional
    public void testSignup_Success() throws Exception {
        // Create signup request
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setUsername(testUsername);
        signupRequest.setEmail(testEmail);
        signupRequest.setPassword(testPassword);
        Set<String> roles = new HashSet<>();
        roles.add("user");
        signupRequest.setRoles(roles);

        // Perform signup request
        ResultActions result = mockMvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest)));

        // Verify response
        result.andExpect(status().isOk())
              .andExpect(jsonPath("$.message").value("User registered successfully!"));

        // Verify user was created in database
        Optional<User> createdUser = userRepository.findByUsername(testUsername);
        assertThat(createdUser).isPresent();
        assertThat(createdUser.get().getEmail()).isEqualTo(testEmail);
        assertThat(passwordEncoder.matches(testPassword, createdUser.get().getPassword())).isTrue();
        assertThat(createdUser.get().getRoles()).hasSize(1);
        assertThat(createdUser.get().getRoles().iterator().next().getName()).isEqualTo(ERole.ROLE_USER);
    }

    @Test
    public void testSignup_DuplicateUsername() throws Exception {
        // Create a user with the test username
        User existingUser = new User(testUsername, "other@example.com", passwordEncoder.encode("otherpassword"));
        Set<Role> roles = new HashSet<>();
        roles.add(roleRepository.findByName(ERole.ROLE_USER).get());
        existingUser.setRoles(roles);
        userRepository.save(existingUser);

        // Create signup request with same username
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setUsername(testUsername);
        signupRequest.setEmail(testEmail);
        signupRequest.setPassword(testPassword);

        // Perform signup request
        ResultActions result = mockMvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest)));

        // Verify response
        result.andExpect(status().isBadRequest())
              .andExpect(jsonPath("$.message").value("Error: Username is already taken!"));
    }

    @Test
    public void testSignup_DuplicateEmail() throws Exception {
        // Create a user with the test email
        User existingUser = new User("otherusername", testEmail, passwordEncoder.encode("otherpassword"));
        Set<Role> roles = new HashSet<>();
        roles.add(roleRepository.findByName(ERole.ROLE_USER).get());
        existingUser.setRoles(roles);
        userRepository.save(existingUser);

        // Create signup request with same email
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setUsername(testUsername);
        signupRequest.setEmail(testEmail);
        signupRequest.setPassword(testPassword);

        // Perform signup request
        ResultActions result = mockMvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest)));

        // Verify response
        result.andExpect(status().isBadRequest())
              .andExpect(jsonPath("$.message").value("Error: Email is already in use!"));
    }

    @Test
    public void testSignin_Success() throws Exception {
        // Create a user for testing
        User user = new User(testUsername, testEmail, passwordEncoder.encode(testPassword));
        Set<Role> roles = new HashSet<>();
        roles.add(roleRepository.findByName(ERole.ROLE_USER).get());
        user.setRoles(roles);
        userRepository.save(user);

        // Create login request
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername(testUsername);
        loginRequest.setPassword(testPassword);

        // Perform login request
        ResultActions result = mockMvc.perform(post("/api/auth/signin")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)));

        // Verify response
        result.andExpect(status().isOk())
              .andExpect(jsonPath("$.username").value(testUsername))
              .andExpect(jsonPath("$.email").value(testEmail))
              .andExpect(jsonPath("$.roles").isArray())
              .andExpect(jsonPath("$.roles[0]").value("ROLE_USER"))
              .andExpect(jsonPath("$.type").value("Bearer"))
              .andExpect(jsonPath("$.token").isNotEmpty());
    }

    @Test
    public void testSignin_InvalidCredentials() throws Exception {
        // Create a user for testing
        User user = new User(testUsername, testEmail, passwordEncoder.encode(testPassword));
        Set<Role> roles = new HashSet<>();
        roles.add(roleRepository.findByName(ERole.ROLE_USER).get());
        user.setRoles(roles);
        userRepository.save(user);

        // Create login request with wrong password
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername(testUsername);
        loginRequest.setPassword("wrongpassword");

        // Perform login request
        ResultActions result = mockMvc.perform(post("/api/auth/signin")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)));

        // Verify response
        result.andExpect(status().isUnauthorized());
    }

    @Test
    public void testSignin_UserNotFound() throws Exception {
        // Create login request with non-existent user
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername("nonexistentuser");
        loginRequest.setPassword(testPassword);

        // Perform login request
        ResultActions result = mockMvc.perform(post("/api/auth/signin")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)));

        // Verify response
        result.andExpect(status().isUnauthorized());
    }
}
