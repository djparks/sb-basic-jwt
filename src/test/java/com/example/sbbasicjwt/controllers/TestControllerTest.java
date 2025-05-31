package com.example.sbbasicjwt.controllers;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import com.example.sbbasicjwt.security.jwt.JwtUtils;
import com.example.sbbasicjwt.security.services.UserDetailsServiceImpl;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class TestControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserDetailsServiceImpl userDetailsService;

    @MockBean
    private JwtUtils jwtUtils;


    @Test
    public void testPublicEndpoint_NoAuth() throws Exception {
        mockMvc.perform(get("/api/public/all"))
                .andExpect(status().isOk())
                .andExpect(content().string("Public Content."));
    }

    @Test
    @WithMockUser(roles = "USER")
    public void testUserEndpoint_WithUserRole() throws Exception {
        mockMvc.perform(get("/api/user"))
                .andExpect(status().isOk())
                .andExpect(content().string("User Content."));
    }

    @Test
    @WithMockUser(roles = "MODERATOR")
    public void testUserEndpoint_WithModRole() throws Exception {
        mockMvc.perform(get("/api/user"))
                .andExpect(status().isOk())
                .andExpect(content().string("User Content."));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void testUserEndpoint_WithAdminRole() throws Exception {
        mockMvc.perform(get("/api/user"))
                .andExpect(status().isOk())
                .andExpect(content().string("User Content."));
    }

    @Test
    public void testUserEndpoint_NoAuth() throws Exception {
        mockMvc.perform(get("/api/user"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "USER")
    public void testModEndpoint_WithUserRole() throws Exception {
        mockMvc.perform(get("/api/mod"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "MODERATOR")
    public void testModEndpoint_WithModRole() throws Exception {
        mockMvc.perform(get("/api/mod"))
                .andExpect(status().isOk())
                .andExpect(content().string("Moderator Board."));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void testModEndpoint_WithAdminRole() throws Exception {
        mockMvc.perform(get("/api/mod"))
                .andExpect(status().isForbidden());
    }

    @Test
    public void testModEndpoint_NoAuth() throws Exception {
        mockMvc.perform(get("/api/mod"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "USER")
    public void testAdminEndpoint_WithUserRole() throws Exception {
        mockMvc.perform(get("/api/admin"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "MODERATOR")
    public void testAdminEndpoint_WithModRole() throws Exception {
        mockMvc.perform(get("/api/admin"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void testAdminEndpoint_WithAdminRole() throws Exception {
        mockMvc.perform(get("/api/admin"))
                .andExpect(status().isOk())
                .andExpect(content().string("Admin Board."));
    }

    @Test
    public void testAdminEndpoint_NoAuth() throws Exception {
        mockMvc.perform(get("/api/admin"))
                .andExpect(status().isUnauthorized());
    }

    // This test is no longer needed as we're using @WithMockUser instead of JWT tokens
}
