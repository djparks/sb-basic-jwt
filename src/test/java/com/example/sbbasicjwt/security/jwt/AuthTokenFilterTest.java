package com.example.sbbasicjwt.security.jwt;

import com.example.sbbasicjwt.security.services.UserDetailsImpl;
import com.example.sbbasicjwt.security.services.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@SpringBootTest
public class AuthTokenFilterTest {

    @Mock
    private JwtUtils jwtUtils;

    @Mock
    private UserDetailsServiceImpl userDetailsService;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @InjectMocks
    private AuthTokenFilter authTokenFilter;

    private UserDetails userDetails;
    private final String validToken = "valid.jwt.token";
    private final String username = "testuser";

    @BeforeEach
    public void setup() {
        // Clear security context before each test
        SecurityContextHolder.clearContext();

        // Create a test user with ROLE_USER authority
        userDetails = new UserDetailsImpl(
                1L,
                username,
                "test@example.com",
                "password",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))
        );
    }

    @Test
    public void testDoFilterInternal_WithValidToken() throws Exception {
        // Mock request to return a valid Authorization header
        when(request.getHeader("Authorization")).thenReturn("Bearer " + validToken);
        
        // Mock JWT utils to validate the token and extract username
        when(jwtUtils.validateJwtToken(validToken)).thenReturn(true);
        when(jwtUtils.getUserNameFromJwtToken(validToken)).thenReturn(username);
        
        // Mock user details service to return our test user
        when(userDetailsService.loadUserByUsername(username)).thenReturn(userDetails);

        // Execute the filter
        authTokenFilter.doFilterInternal(request, response, filterChain);

        // Verify that the filter chain was called
        verify(filterChain).doFilter(request, response);
        
        // Verify that the authentication was set in the security context
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication().getPrincipal()).isEqualTo(userDetails);
    }

    @Test
    public void testDoFilterInternal_WithInvalidToken() throws Exception {
        // Mock request to return an invalid Authorization header
        when(request.getHeader("Authorization")).thenReturn("Bearer invalidToken");
        
        // Mock JWT utils to invalidate the token
        when(jwtUtils.validateJwtToken("invalidToken")).thenReturn(false);

        // Execute the filter
        authTokenFilter.doFilterInternal(request, response, filterChain);

        // Verify that the filter chain was called
        verify(filterChain).doFilter(request, response);
        
        // Verify that no authentication was set in the security context
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        
        // Verify that user details service was not called
        verify(userDetailsService, never()).loadUserByUsername(anyString());
    }

    @Test
    public void testDoFilterInternal_WithNoToken() throws Exception {
        // Mock request to return no Authorization header
        when(request.getHeader("Authorization")).thenReturn(null);

        // Execute the filter
        authTokenFilter.doFilterInternal(request, response, filterChain);

        // Verify that the filter chain was called
        verify(filterChain).doFilter(request, response);
        
        // Verify that no authentication was set in the security context
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        
        // Verify that JWT utils and user details service were not called
        verify(jwtUtils, never()).validateJwtToken(anyString());
        verify(userDetailsService, never()).loadUserByUsername(anyString());
    }

    @Test
    public void testDoFilterInternal_WithNonBearerToken() throws Exception {
        // Mock request to return a non-Bearer Authorization header
        when(request.getHeader("Authorization")).thenReturn("Basic dXNlcjpwYXNzd29yZA==");

        // Execute the filter
        authTokenFilter.doFilterInternal(request, response, filterChain);

        // Verify that the filter chain was called
        verify(filterChain).doFilter(request, response);
        
        // Verify that no authentication was set in the security context
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        
        // Verify that JWT utils and user details service were not called
        verify(jwtUtils, never()).validateJwtToken(anyString());
        verify(userDetailsService, never()).loadUserByUsername(anyString());
    }

    @Test
    public void testDoFilterInternal_WithException() throws Exception {
        // Mock request to return a valid Authorization header
        when(request.getHeader("Authorization")).thenReturn("Bearer " + validToken);
        
        // Mock JWT utils to throw an exception
        when(jwtUtils.validateJwtToken(validToken)).thenThrow(new RuntimeException("Test exception"));

        // Execute the filter
        authTokenFilter.doFilterInternal(request, response, filterChain);

        // Verify that the filter chain was called despite the exception
        verify(filterChain).doFilter(request, response);
        
        // Verify that no authentication was set in the security context
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }
}