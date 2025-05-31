package com.example.sbbasicjwt.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for testing endpoints with different authorization levels.
 */
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api")
public class TestController {
    
    /**
     * Public endpoint that can be accessed without authentication.
     *
     * @return a welcome message
     */
    @GetMapping("/public/all")
    public String allAccess() {
        return "Public Content.";
    }

    /**
     * Secured endpoint that can be accessed by any authenticated user.
     *
     * @return a user content message
     */
    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public String userAccess() {
        return "User Content.";
    }

    /**
     * Secured endpoint that can only be accessed by users with MODERATOR role.
     *
     * @return a moderator content message
     */
    @GetMapping("/mod")
    @PreAuthorize("hasRole('MODERATOR')")
    public String moderatorAccess() {
        return "Moderator Board.";
    }

    /**
     * Secured endpoint that can only be accessed by users with ADMIN role.
     *
     * @return an admin content message
     */
    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess() {
        return "Admin Board.";
    }
}