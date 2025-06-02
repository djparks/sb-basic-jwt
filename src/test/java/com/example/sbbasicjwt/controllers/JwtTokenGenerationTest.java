package com.example.sbbasicjwt.controllers;

import com.example.sbbasicjwt.model.ERole;
import com.example.sbbasicjwt.model.Role;
import com.example.sbbasicjwt.model.User;
import com.example.sbbasicjwt.payload.request.LoginRequest;
import com.example.sbbasicjwt.repository.RoleRepository;
import com.example.sbbasicjwt.repository.UserRepository;
import com.example.sbbasicjwt.security.jwt.JwtUtils;
import com.example.sbbasicjwt.security.services.UserDetailsImpl;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Collections;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for JWT token generation and usage.
 * This class demonstrates how to generate real JWT tokens and use them in tests.
 */
@SpringBootTest
@AutoConfigureMockMvc
public class JwtTokenGenerationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private UserRepository userRepository;

    @MockBean
    private RoleRepository roleRepository;

    @MockBean
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtils jwtUtils;

    private final String testUsername = "testuser";
    private final String testEmail = "test@example.com";
    private final String testPassword = "password123";

    @BeforeEach
    public void setup() {
        // Mock user with USER role
        UserDetailsImpl userDetails = new UserDetailsImpl(
                1L,
                testUsername,
                testEmail,
                "encodedPassword",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))
        );

        // Mock user with MODERATOR role
        UserDetailsImpl modDetails = new UserDetailsImpl(
                2L,
                "moduser",
                "mod@example.com",
                "encodedPassword",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_MODERATOR"))
        );

        // Mock user with ADMIN role
        UserDetailsImpl adminDetails = new UserDetailsImpl(
                3L,
                "adminuser",
                "admin@example.com",
                "encodedPassword",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );

        // Mock authentication for USER role
        Authentication userAuth = mock(Authentication.class);
        when(userAuth.getPrincipal()).thenReturn(userDetails);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(userAuth);

        // Mock user repository
        User userWithUserRole = new User(testUsername, testEmail, "encodedPassword");
        Role userRole = new Role(ERole.ROLE_USER);
        userWithUserRole.setRoles(Collections.singleton(userRole));
        when(userRepository.findByUsername(testUsername)).thenReturn(Optional.of(userWithUserRole));
    }

    @Test
    public void testGenerateAndUseJwtToken() throws Exception {
        // Create login request
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername(testUsername);
        loginRequest.setPassword(testPassword);

        // Perform login to get JWT token
        MvcResult result = mockMvc.perform(post("/api/auth/signin")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andReturn();

        // Extract token from response
        String response = result.getResponse().getContentAsString();
        String token = objectMapper.readTree(response).get("token").asText();
        assertNotNull(token, "JWT token should not be null");

        // Use the token to access a protected endpoint
        mockMvc.perform(get("/api/user")
                .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string("User Content."));
    }

    @Test
    public void testGenerateAndUseJwtToken_WithInvalidCredentials() throws Exception {
        // Mock authentication to throw exception for invalid credentials
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new org.springframework.security.authentication.BadCredentialsException("Bad credentials"));

        // Create login request with invalid credentials
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername(testUsername);
        loginRequest.setPassword("wrongpassword");

        // Perform login with invalid credentials
        mockMvc.perform(post("/api/auth/signin")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void testAccessProtectedEndpoint_WithoutToken() throws Exception {
        // Try to access protected endpoint without token
        mockMvc.perform(get("/api/user"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void testAccessProtectedEndpoint_WithInvalidToken() throws Exception {
        // Try to access protected endpoint with invalid token
        mockMvc.perform(get("/api/user")
                .header("Authorization", "Bearer invalidtoken"))
                .andExpect(status().isUnauthorized());
    }
}