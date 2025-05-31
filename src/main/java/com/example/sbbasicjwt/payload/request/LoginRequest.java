package com.example.sbbasicjwt.payload.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Payload class for login requests.
 */
@Data
public class LoginRequest {
    @NotBlank
    private String username;

    @NotBlank
    private String password;
}