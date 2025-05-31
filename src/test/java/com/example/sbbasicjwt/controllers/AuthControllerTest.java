package com.example.sbbasicjwt.controllers;

import com.example.sbbasicjwt.model.ERole;
import com.example.sbbasicjwt.model.Role;
import com.example.sbbasicjwt.model.User;
import com.example.sbbasicjwt.payload.request.LoginRequest;
import com.example.sbbasicjwt.payload.request.SignupRequest;
import com.example.sbbasicjwt.payload.response.JwtResponse;
import com.example.sbbasicjwt.payload.response.MessageResponse;
import com.example.sbbasicjwt.repository.RoleRepository;
import com.example.sbbasicjwt.repository.UserRepository;
import com.example.sbbasicjwt.security.jwt.JwtUtils;
import com.example.sbbasicjwt.security.services.UserDetailsImpl;
import com.example.sbbasicjwt.security.services.UserDetailsServiceImpl;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class AuthControllerTest {

    @MockBean
    private UserDetailsServiceImpl userDetailsService;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private UserRepository userRepository;

    @MockBean
    private RoleRepository roleRepository;

    @MockBean
    private PasswordEncoder passwordEncoder;

    @MockBean
    private JwtUtils jwtUtils;

    @MockBean
    private AuthenticationManager authenticationManager;

    private final String testUsername = "testuser";
    private final String testEmail = "test@example.com";
    private final String testPassword = "password123";

    // No setup needed as we're using mocked dependencies

    @Test
    public void testSignup_Success() throws Exception {
        // Setup mocks
        when(userRepository.existsByUsername(testUsername)).thenReturn(false);
        when(userRepository.existsByEmail(testEmail)).thenReturn(false);

        Role userRole = new Role(ERole.ROLE_USER);
        when(roleRepository.findByName(ERole.ROLE_USER)).thenReturn(Optional.of(userRole));

        when(passwordEncoder.encode(testPassword)).thenReturn("encodedPassword");

        // Create signup request
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setUsername(testUsername);
        signupRequest.setEmail(testEmail);
        signupRequest.setPassword(testPassword);
        Set<String> roles = new HashSet<>();
        roles.add("user");
        signupRequest.setRoles(roles);

        // Perform signup request
        mockMvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("User registered successfully!"));
    }

    @Test
    public void testSignup_DuplicateUsername() throws Exception {
        // Setup mocks
        when(userRepository.existsByUsername(testUsername)).thenReturn(true);

        // Create signup request with same username
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setUsername(testUsername);
        signupRequest.setEmail(testEmail);
        signupRequest.setPassword(testPassword);

        // Perform signup request
        mockMvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Error: Username is already taken!"));
    }

    @Test
    public void testSignup_DuplicateEmail() throws Exception {
        // Setup mocks
        when(userRepository.existsByUsername(testUsername)).thenReturn(false);
        when(userRepository.existsByEmail(testEmail)).thenReturn(true);

        // Create signup request with same email
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setUsername(testUsername);
        signupRequest.setEmail(testEmail);
        signupRequest.setPassword(testPassword);

        // Perform signup request
        mockMvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Error: Email is already in use!"));
    }

    @Test
    public void testSignin_Success() throws Exception {
        // Setup mocks
        // Create UserDetailsImpl
        UserDetailsImpl userDetails = new UserDetailsImpl(
            1L, 
            testUsername, 
            testEmail, 
            "encodedPassword", 
            Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))
        );

        // Mock authentication
        Authentication authentication = Mockito.mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
            .thenReturn(authentication);

        // Mock JWT generation
        when(jwtUtils.generateJwtToken(any(Authentication.class))).thenReturn("mocked-jwt-token");

        // Create login request
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername(testUsername);
        loginRequest.setPassword(testPassword);

        // Perform login request
        mockMvc.perform(post("/api/auth/signin")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(testUsername))
                .andExpect(jsonPath("$.email").value(testEmail))
                .andExpect(jsonPath("$.roles").isArray())
                .andExpect(jsonPath("$.roles[0]").value("ROLE_USER"))
                .andExpect(jsonPath("$.type").value("Bearer"))
                .andExpect(jsonPath("$.token").value("mocked-jwt-token"));
    }

    @Test
    public void testSignin_InvalidCredentials() throws Exception {
        // Setup mocks
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
            .thenThrow(new org.springframework.security.authentication.BadCredentialsException("Bad credentials"));

        // Create login request with wrong password
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername(testUsername);
        loginRequest.setPassword("wrongpassword");

        // Perform login request
        mockMvc.perform(post("/api/auth/signin")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void testSignin_UserNotFound() throws Exception {
        // Setup mocks
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
            .thenThrow(new org.springframework.security.authentication.BadCredentialsException("Bad credentials"));

        // Create login request with non-existent user
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername("nonexistentuser");
        loginRequest.setPassword(testPassword);

        // Perform login request
        mockMvc.perform(post("/api/auth/signin")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized());
    }
}
