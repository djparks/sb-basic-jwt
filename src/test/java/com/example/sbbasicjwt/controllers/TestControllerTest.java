package com.example.sbbasicjwt.controllers;

import com.example.sbbasicjwt.model.ERole;
import com.example.sbbasicjwt.model.Role;
import com.example.sbbasicjwt.model.User;
import com.example.sbbasicjwt.repository.RoleRepository;
import com.example.sbbasicjwt.repository.UserRepository;
import com.example.sbbasicjwt.security.jwt.JwtUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.util.HashSet;
import java.util.Set;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class TestControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private AuthenticationManager authenticationManager;

    private final String userUsername = "testuser";
    private final String modUsername = "testmod";
    private final String adminUsername = "testadmin";
    private final String password = "password123";
    private final String email = "test@example.com";

    private String userToken;
    private String modToken;
    private String adminToken;

    @BeforeEach
    public void setup() {
        // Clean up test users
        userRepository.findByUsername(userUsername).ifPresent(userRepository::delete);
        userRepository.findByUsername(modUsername).ifPresent(userRepository::delete);
        userRepository.findByUsername(adminUsername).ifPresent(userRepository::delete);

        // Ensure roles exist
        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                .orElseGet(() -> roleRepository.save(new Role(ERole.ROLE_USER)));
        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                .orElseGet(() -> roleRepository.save(new Role(ERole.ROLE_MODERATOR)));
        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                .orElseGet(() -> roleRepository.save(new Role(ERole.ROLE_ADMIN)));

        // Create test users with different roles
        // User with ROLE_USER
        User user = new User(userUsername, email + ".user", passwordEncoder.encode(password));
        Set<Role> userRoles = new HashSet<>();
        userRoles.add(userRole);
        user.setRoles(userRoles);
        userRepository.save(user);

        // User with ROLE_MODERATOR
        User mod = new User(modUsername, email + ".mod", passwordEncoder.encode(password));
        Set<Role> modRoles = new HashSet<>();
        modRoles.add(userRole);
        modRoles.add(modRole);
        mod.setRoles(modRoles);
        userRepository.save(mod);

        // User with ROLE_ADMIN
        User admin = new User(adminUsername, email + ".admin", passwordEncoder.encode(password));
        Set<Role> adminRoles = new HashSet<>();
        adminRoles.add(userRole);
        adminRoles.add(adminRole);
        admin.setRoles(adminRoles);
        userRepository.save(admin);

        // Generate tokens for each user
        userToken = generateToken(userUsername, password);
        modToken = generateToken(modUsername, password);
        adminToken = generateToken(adminUsername, password);
    }

    private String generateToken(String username, String password) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password));
        return jwtUtils.generateJwtToken(authentication);
    }

    @Test
    public void testPublicEndpoint_NoAuth() throws Exception {
        mockMvc.perform(get("/api/public/all"))
                .andExpect(status().isOk())
                .andExpect(content().string("Public Content."));
    }

    @Test
    public void testUserEndpoint_WithUserRole() throws Exception {
        mockMvc.perform(get("/api/user")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(content().string("User Content."));
    }

    @Test
    public void testUserEndpoint_WithModRole() throws Exception {
        mockMvc.perform(get("/api/user")
                .header("Authorization", "Bearer " + modToken))
                .andExpect(status().isOk())
                .andExpect(content().string("User Content."));
    }

    @Test
    public void testUserEndpoint_WithAdminRole() throws Exception {
        mockMvc.perform(get("/api/user")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(content().string("User Content."));
    }

    @Test
    public void testUserEndpoint_NoAuth() throws Exception {
        mockMvc.perform(get("/api/user"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void testModEndpoint_WithUserRole() throws Exception {
        mockMvc.perform(get("/api/mod")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    public void testModEndpoint_WithModRole() throws Exception {
        mockMvc.perform(get("/api/mod")
                .header("Authorization", "Bearer " + modToken))
                .andExpect(status().isOk())
                .andExpect(content().string("Moderator Board."));
    }

    @Test
    public void testModEndpoint_WithAdminRole() throws Exception {
        mockMvc.perform(get("/api/mod")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isForbidden());
    }

    @Test
    public void testModEndpoint_NoAuth() throws Exception {
        mockMvc.perform(get("/api/mod"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void testAdminEndpoint_WithUserRole() throws Exception {
        mockMvc.perform(get("/api/admin")
                .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    public void testAdminEndpoint_WithModRole() throws Exception {
        mockMvc.perform(get("/api/admin")
                .header("Authorization", "Bearer " + modToken))
                .andExpect(status().isForbidden());
    }

    @Test
    public void testAdminEndpoint_WithAdminRole() throws Exception {
        mockMvc.perform(get("/api/admin")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(content().string("Admin Board."));
    }

    @Test
    public void testAdminEndpoint_NoAuth() throws Exception {
        mockMvc.perform(get("/api/admin"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void testInvalidToken() throws Exception {
        mockMvc.perform(get("/api/user")
                .header("Authorization", "Bearer invalidtoken"))
                .andExpect(status().isUnauthorized());
    }
}