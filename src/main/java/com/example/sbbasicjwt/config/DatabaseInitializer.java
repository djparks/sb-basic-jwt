package com.example.sbbasicjwt.config;

import com.example.sbbasicjwt.model.ERole;
import com.example.sbbasicjwt.model.Role;
import com.example.sbbasicjwt.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.Arrays;

/**
 * Database initializer to populate the roles table with predefined roles.
 */
@Component
public class DatabaseInitializer implements CommandLineRunner {

    @Autowired
    private RoleRepository roleRepository;

    /**
     * Initialize the database with predefined roles.
     *
     * @param args command line arguments
     */
    @Override
    public void run(String... args) {
        // Check if roles already exist
        if (roleRepository.count() == 0) {
            // Create roles
            Role userRole = new Role(ERole.ROLE_USER);
            Role modRole = new Role(ERole.ROLE_MODERATOR);
            Role adminRole = new Role(ERole.ROLE_ADMIN);

            // Save roles to database
            roleRepository.saveAll(Arrays.asList(userRole, modRole, adminRole));
            
            System.out.println("Database initialized with predefined roles");
        }
    }
}