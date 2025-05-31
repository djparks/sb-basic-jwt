package com.example.sbbasicjwt.security.services;

import com.example.sbbasicjwt.model.ERole;
import com.example.sbbasicjwt.model.Role;
import com.example.sbbasicjwt.model.User;
import com.example.sbbasicjwt.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@SpringBootTest
public class UserDetailsServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserDetailsServiceImpl userDetailsService;

    private User user;
    private final String username = "testuser";
    private final String email = "test@example.com";
    private final String password = "password";

    @BeforeEach
    public void setup() {
        // Create a test user with ROLE_USER
        user = new User();
        user.setId(1L);
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(password);
        
        Set<Role> roles = new HashSet<>();
        Role userRole = new Role(ERole.ROLE_USER);
        roles.add(userRole);
        user.setRoles(roles);
    }

    @Test
    public void testLoadUserByUsername_Success() {
        // Mock repository to return our test user
        when(userRepository.findByUsername(username)).thenReturn(Optional.of(user));

        // Call the service
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        // Verify the result
        assertThat(userDetails).isNotNull();
        assertThat(userDetails.getUsername()).isEqualTo(username);
        assertThat(userDetails.getPassword()).isEqualTo(password);
        assertThat(userDetails.getAuthorities()).hasSize(1);
        assertThat(userDetails.getAuthorities().iterator().next().getAuthority()).isEqualTo("ROLE_USER");
        assertThat(userDetails).isInstanceOf(UserDetailsImpl.class);
        
        UserDetailsImpl userDetailsImpl = (UserDetailsImpl) userDetails;
        assertThat(userDetailsImpl.getId()).isEqualTo(1L);
        assertThat(userDetailsImpl.getEmail()).isEqualTo(email);
    }

    @Test
    public void testLoadUserByUsername_UserNotFound() {
        // Mock repository to return empty optional
        when(userRepository.findByUsername("nonexistentuser")).thenReturn(Optional.empty());

        // Verify that UsernameNotFoundException is thrown
        assertThatThrownBy(() -> userDetailsService.loadUserByUsername("nonexistentuser"))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("User Not Found with username: nonexistentuser");
    }

    @Test
    public void testLoadUserByUsername_WithMultipleRoles() {
        // Add ROLE_ADMIN to the user
        Role adminRole = new Role(ERole.ROLE_ADMIN);
        user.getRoles().add(adminRole);

        // Mock repository to return our test user with multiple roles
        when(userRepository.findByUsername(username)).thenReturn(Optional.of(user));

        // Call the service
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        // Verify the result
        assertThat(userDetails).isNotNull();
        assertThat(userDetails.getAuthorities()).hasSize(2);
        assertThat(userDetails.getAuthorities().stream()
                .map(authority -> authority.getAuthority())
                .toList())
                .contains("ROLE_USER", "ROLE_ADMIN");
    }
}