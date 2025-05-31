package com.example.sbbasicjwt.payload.response;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * Payload class for message responses.
 */
@Data
@AllArgsConstructor
public class MessageResponse {
    private String message;
}