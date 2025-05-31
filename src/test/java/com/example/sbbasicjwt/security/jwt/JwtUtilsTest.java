package com.example.sbbasicjwt.security.jwt;

import com.example.sbbasicjwt.security.services.UserDetailsImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class JwtUtilsTest {

    private JwtUtils jwtUtils;

    private UserDetailsImpl userDetails;
    private Authentication authentication;

    @BeforeEach
    public void setup() {
        // Initialize JwtUtils
        jwtUtils = new JwtUtils();

        // Set properties
        ReflectionTestUtils.setField(jwtUtils, "jwtSecret", "testSecretKeyForJwtThatIsLongEnoughToMeetTheMinimumRequirementOf256Bits");
        ReflectionTestUtils.setField(jwtUtils, "jwtExpirationMs", 60000);

        // Create a test user with ROLE_USER authority
        userDetails = new UserDetailsImpl(
                1L,
                "testuser",
                "test@example.com",
                "password",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))
        );

        // Create authentication object
        authentication = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
    }

    @Test
    public void testGenerateJwtToken() {
        // Generate token
        String token = jwtUtils.generateJwtToken(authentication);

        // Verify token is not null or empty
        assertThat(token).isNotNull().isNotEmpty();
    }

    @Test
    public void testGetUserNameFromJwtToken() {
        // Generate token
        String token = jwtUtils.generateJwtToken(authentication);

        // Extract username from token
        String username = jwtUtils.getUserNameFromJwtToken(token);

        // Verify extracted username matches original username
        assertThat(username).isEqualTo(userDetails.getUsername());
    }

    @Test
    public void testValidateJwtToken() {
        // Generate token
        String token = jwtUtils.generateJwtToken(authentication);

        // Validate token
        boolean isValid = jwtUtils.validateJwtToken(token);

        // Verify token is valid
        assertThat(isValid).isTrue();
    }

    @Test
    public void testValidateInvalidJwtToken() {
        // Test with invalid token
        boolean isValid = jwtUtils.validateJwtToken("invalidToken");

        // Verify token is invalid
        assertThat(isValid).isFalse();
    }

    @Test
    public void testValidateExpiredJwtToken() throws Exception {
        // Set a very short expiration time for this test
        ReflectionTestUtils.setField(jwtUtils, "jwtExpirationMs", 1);

        // Generate token that will expire almost immediately
        String token = jwtUtils.generateJwtToken(authentication);

        // Wait for token to expire
        Thread.sleep(10);

        // Validate expired token
        boolean isValid = jwtUtils.validateJwtToken(token);

        // Verify token is invalid
        assertThat(isValid).isFalse();
    }
}
