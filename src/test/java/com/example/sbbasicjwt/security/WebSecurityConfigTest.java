package com.example.sbbasicjwt.security;

import com.example.sbbasicjwt.security.jwt.AuthEntryPointJwt;
import com.example.sbbasicjwt.security.jwt.AuthTokenFilter;
import com.example.sbbasicjwt.security.services.UserDetailsServiceImpl;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SpringBootTest
public class WebSecurityConfigTest {

    @Autowired
    private WebSecurityConfig webSecurityConfig;

    @MockBean
    private UserDetailsServiceImpl userDetailsService;

    @MockBean
    private AuthEntryPointJwt unauthorizedHandler;

    @Test
    public void testAuthenticationJwtTokenFilter() {
        AuthTokenFilter filter = webSecurityConfig.authenticationJwtTokenFilter();
        assertNotNull(filter, "AuthTokenFilter should not be null");
    }

    @Test
    public void testAuthenticationProvider() {
        DaoAuthenticationProvider provider = webSecurityConfig.authenticationProvider();
        assertNotNull(provider, "DaoAuthenticationProvider should not be null");
    }

    @Test
    public void testPasswordEncoder() {
        PasswordEncoder encoder = webSecurityConfig.passwordEncoder();
        assertNotNull(encoder, "PasswordEncoder should not be null");

        // Test that the encoder works as expected
        String password = "testPassword";
        String encodedPassword = encoder.encode(password);
        assertNotEquals(password, encodedPassword, "Encoded password should be different from raw password");
        assertTrue(encoder.matches(password, encodedPassword), "Password should match its encoded version");
    }

    @Test
    public void testAuthenticationManager() throws Exception {
        // In a real application, the AuthenticationConfiguration would be provided by Spring
        // and would return the actual AuthenticationManager
        AuthenticationConfiguration authConfig = mock(AuthenticationConfiguration.class);
        AuthenticationManager authManager = mock(AuthenticationManager.class);
        when(authConfig.getAuthenticationManager()).thenReturn(authManager);

        AuthenticationManager result = webSecurityConfig.authenticationManager(authConfig);
        assertNotNull(result, "AuthenticationManager should not be null");
    }

    @Test
    public void testFilterChain() throws Exception {
        SecurityFilterChain filterChain = webSecurityConfig.filterChain(mock(org.springframework.security.config.annotation.web.builders.HttpSecurity.class));
        assertNotNull(filterChain, "SecurityFilterChain should not be null");
    }
}
