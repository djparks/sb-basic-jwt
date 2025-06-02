package com.example.sbbasicjwt.controllers;

import com.example.sbbasicjwt.model.ERole;
import com.example.sbbasicjwt.model.Role;
import com.example.sbbasicjwt.model.User;
import com.example.sbbasicjwt.repository.RoleRepository;
import com.example.sbbasicjwt.repository.UserRepository;
import com.example.sbbasicjwt.security.jwt.JwtUtils;
import com.example.sbbasicjwt.security.services.UserDetailsImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for JWT token-based authentication.
 */
@SpringBootTest
@AutoConfigureMockMvc
public class JwtAuthenticationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private JwtUtils jwtUtils;

    @MockBean
    private UserRepository userRepository;

    @MockBean
    private RoleRepository roleRepository;

    @MockBean
    private AuthenticationManager authenticationManager;

    private final String testUsername = "testuser";
    private final String testEmail = "test@example.com";
    private final String testPassword = "password123";
    private final String validUserToken = "valid-user-token";
    private final String validModeratorToken = "valid-moderator-token";
    private final String validAdminToken = "valid-admin-token";
    private final String invalidToken = "invalid-token";
    private final String expiredToken = "expired-token";

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

        // Mock JWT validation
        when(jwtUtils.validateJwtToken(validUserToken)).thenReturn(true);
        when(jwtUtils.validateJwtToken(validModeratorToken)).thenReturn(true);
        when(jwtUtils.validateJwtToken(validAdminToken)).thenReturn(true);
        when(jwtUtils.validateJwtToken(invalidToken)).thenReturn(false);
        when(jwtUtils.validateJwtToken(expiredToken)).thenReturn(false);

        // Mock username extraction from tokens
        when(jwtUtils.getUserNameFromJwtToken(validUserToken)).thenReturn(testUsername);
        when(jwtUtils.getUserNameFromJwtToken(validModeratorToken)).thenReturn("moduser");
        when(jwtUtils.getUserNameFromJwtToken(validAdminToken)).thenReturn("adminuser");

        // Mock user repository
        User userWithUserRole = new User(testUsername, testEmail, "encodedPassword");
        Role userRole = new Role(ERole.ROLE_USER);
        userWithUserRole.setRoles(Collections.singleton(userRole));
        when(userRepository.findByUsername(testUsername)).thenReturn(Optional.of(userWithUserRole));

        User userWithModRole = new User("moduser", "mod@example.com", "encodedPassword");
        Role modRole = new Role(ERole.ROLE_MODERATOR);
        userWithModRole.setRoles(Collections.singleton(modRole));
        when(userRepository.findByUsername("moduser")).thenReturn(Optional.of(userWithModRole));

        User userWithAdminRole = new User("adminuser", "admin@example.com", "encodedPassword");
        Role adminRole = new Role(ERole.ROLE_ADMIN);
        userWithAdminRole.setRoles(Collections.singleton(adminRole));
        when(userRepository.findByUsername("adminuser")).thenReturn(Optional.of(userWithAdminRole));
    }

    @Test
    public void testPublicEndpoint_WithJwt() throws Exception {
        // Public endpoint should be accessible with any token
        mockMvc.perform(get("/api/public/all")
                .header("Authorization", "Bearer " + validUserToken))
                .andExpect(status().isOk())
                .andExpect(content().string("Public Content."));
    }

    @Test
    public void testUserEndpoint_WithValidUserToken() throws Exception {
        mockMvc.perform(get("/api/user")
                .header("Authorization", "Bearer " + validUserToken))
                .andExpect(status().isOk())
                .andExpect(content().string("User Content."));
    }

    @Test
    public void testUserEndpoint_WithValidModeratorToken() throws Exception {
        mockMvc.perform(get("/api/user")
                .header("Authorization", "Bearer " + validModeratorToken))
                .andExpect(status().isOk())
                .andExpect(content().string("User Content."));
    }

    @Test
    public void testUserEndpoint_WithValidAdminToken() throws Exception {
        mockMvc.perform(get("/api/user")
                .header("Authorization", "Bearer " + validAdminToken))
                .andExpect(status().isOk())
                .andExpect(content().string("User Content."));
    }

    @Test
    public void testModEndpoint_WithValidUserToken() throws Exception {
        mockMvc.perform(get("/api/mod")
                .header("Authorization", "Bearer " + validUserToken))
                .andExpect(status().isForbidden());
    }

    @Test
    public void testModEndpoint_WithValidModeratorToken() throws Exception {
        mockMvc.perform(get("/api/mod")
                .header("Authorization", "Bearer " + validModeratorToken))
                .andExpect(status().isOk())
                .andExpect(content().string("Moderator Board."));
    }

    @Test
    public void testModEndpoint_WithValidAdminToken() throws Exception {
        mockMvc.perform(get("/api/mod")
                .header("Authorization", "Bearer " + validAdminToken))
                .andExpect(status().isForbidden());
    }

    @Test
    public void testAdminEndpoint_WithValidUserToken() throws Exception {
        mockMvc.perform(get("/api/admin")
                .header("Authorization", "Bearer " + validUserToken))
                .andExpect(status().isForbidden());
    }

    @Test
    public void testAdminEndpoint_WithValidModeratorToken() throws Exception {
        mockMvc.perform(get("/api/admin")
                .header("Authorization", "Bearer " + validModeratorToken))
                .andExpect(status().isForbidden());
    }

    @Test
    public void testAdminEndpoint_WithValidAdminToken() throws Exception {
        mockMvc.perform(get("/api/admin")
                .header("Authorization", "Bearer " + validAdminToken))
                .andExpect(status().isOk())
                .andExpect(content().string("Admin Board."));
    }

    @Test
    public void testProtectedEndpoint_WithInvalidToken() throws Exception {
        mockMvc.perform(get("/api/user")
                .header("Authorization", "Bearer " + invalidToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void testProtectedEndpoint_WithExpiredToken() throws Exception {
        mockMvc.perform(get("/api/user")
                .header("Authorization", "Bearer " + expiredToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void testProtectedEndpoint_WithNoToken() throws Exception {
        mockMvc.perform(get("/api/user"))
                .andExpect(status().isUnauthorized());
    }
}