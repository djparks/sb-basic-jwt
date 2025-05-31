package com.example.sbbasicjwt.security.services;

import com.example.sbbasicjwt.model.ERole;
import com.example.sbbasicjwt.model.Role;
import com.example.sbbasicjwt.model.User;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

public class UserDetailsImplTest {

    @Test
    public void testBuild() {
        // Create a test user
        User user = new User();
        user.setId(1L);
        user.setUsername("testuser");
        user.setEmail("test@example.com");
        user.setPassword("password");
        
        Set<Role> roles = new HashSet<>();
        roles.add(new Role(ERole.ROLE_USER));
        user.setRoles(roles);

        // Build UserDetailsImpl from User
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);

        // Verify the result
        assertThat(userDetails).isNotNull();
        assertThat(userDetails.getId()).isEqualTo(1L);
        assertThat(userDetails.getUsername()).isEqualTo("testuser");
        assertThat(userDetails.getEmail()).isEqualTo("test@example.com");
        assertThat(userDetails.getPassword()).isEqualTo("password");
        assertThat(userDetails.getAuthorities()).hasSize(1);
        assertThat(userDetails.getAuthorities().iterator().next().getAuthority()).isEqualTo("ROLE_USER");
    }

    @Test
    public void testBuildWithMultipleRoles() {
        // Create a test user with multiple roles
        User user = new User();
        user.setId(1L);
        user.setUsername("testuser");
        user.setEmail("test@example.com");
        user.setPassword("password");
        
        Set<Role> roles = new HashSet<>();
        roles.add(new Role(ERole.ROLE_USER));
        roles.add(new Role(ERole.ROLE_ADMIN));
        user.setRoles(roles);

        // Build UserDetailsImpl from User
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);

        // Verify the result
        assertThat(userDetails).isNotNull();
        assertThat(userDetails.getAuthorities()).hasSize(2);
        
        Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
        List<String> authorityNames = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        
        assertThat(authorityNames).contains("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    public void testConstructor() {
        // Create authorities
        List<GrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority("ROLE_USER")
        );

        // Create UserDetailsImpl directly
        UserDetailsImpl userDetails = new UserDetailsImpl(
                1L, "testuser", "test@example.com", "password", authorities);

        // Verify the result
        assertThat(userDetails).isNotNull();
        assertThat(userDetails.getId()).isEqualTo(1L);
        assertThat(userDetails.getUsername()).isEqualTo("testuser");
        assertThat(userDetails.getEmail()).isEqualTo("test@example.com");
        assertThat(userDetails.getPassword()).isEqualTo("password");
        assertThat(userDetails.getAuthorities()).isEqualTo(authorities);
    }

    @Test
    public void testAccountMethods() {
        // Create UserDetailsImpl
        UserDetailsImpl userDetails = new UserDetailsImpl(
                1L, "testuser", "test@example.com", "password", 
                List.of(new SimpleGrantedAuthority("ROLE_USER")));

        // Verify account methods
        assertThat(userDetails.isAccountNonExpired()).isTrue();
        assertThat(userDetails.isAccountNonLocked()).isTrue();
        assertThat(userDetails.isCredentialsNonExpired()).isTrue();
        assertThat(userDetails.isEnabled()).isTrue();
    }

    @Test
    public void testEqualsAndHashCode() {
        // Create two UserDetailsImpl with same ID
        UserDetailsImpl userDetails1 = new UserDetailsImpl(
                1L, "user1", "user1@example.com", "password1", 
                List.of(new SimpleGrantedAuthority("ROLE_USER")));
        
        UserDetailsImpl userDetails2 = new UserDetailsImpl(
                1L, "user2", "user2@example.com", "password2", 
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        
        // Create another UserDetailsImpl with different ID
        UserDetailsImpl userDetails3 = new UserDetailsImpl(
                2L, "user1", "user1@example.com", "password1", 
                List.of(new SimpleGrantedAuthority("ROLE_USER")));

        // Test equals
        assertThat(userDetails1.equals(userDetails1)).isTrue(); // Same object
        assertThat(userDetails1.equals(userDetails2)).isTrue(); // Same ID
        assertThat(userDetails1.equals(userDetails3)).isFalse(); // Different ID
        assertThat(userDetails1.equals(null)).isFalse(); // Null
        assertThat(userDetails1.equals("string")).isFalse(); // Different type

        // Test hashCode
        assertThat(userDetails1.hashCode()).isEqualTo(userDetails2.hashCode()); // Same ID
        assertThat(userDetails1.hashCode()).isNotEqualTo(userDetails3.hashCode()); // Different ID
    }
}