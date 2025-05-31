package com.example.sbbasicjwt.security.jwt;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.PrintWriter;
import java.io.StringWriter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@SpringBootTest
public class AuthEntryPointJwtTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private AuthenticationException authException;

    @InjectMocks
    private AuthEntryPointJwt authEntryPointJwt;

    private StringWriter stringWriter;
    private PrintWriter printWriter;

    @BeforeEach
    public void setup() throws Exception {
        stringWriter = new StringWriter();
        printWriter = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(printWriter);
    }

    @Test
    public void testCommence() throws Exception {
        // Mock the request and exception
        when(request.getServletPath()).thenReturn("/api/test");
        when(authException.getMessage()).thenReturn("Unauthorized");

        // Call the method
        authEntryPointJwt.commence(request, response, authException);

        // Verify response error
        verify(response).sendError(HttpServletResponse.SC_UNAUTHORIZED, "Error: Unauthorized");
    }

    @Test
    public void testImplementsAuthenticationEntryPoint() {
        // Verify that AuthEntryPointJwt implements AuthenticationEntryPoint
        assertThat(authEntryPointJwt).isInstanceOf(AuthenticationEntryPoint.class);
    }

    @Test
    public void testCommenceWithNullMessage() throws Exception {
        // Mock the request and exception with null message
        when(request.getServletPath()).thenReturn("/api/test");
        when(authException.getMessage()).thenReturn(null);

        // Call the method
        authEntryPointJwt.commence(request, response, authException);

        // Verify response error
        verify(response).sendError(HttpServletResponse.SC_UNAUTHORIZED, "Error: Unauthorized");
    }
}
