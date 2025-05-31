package com.example.sbbasicjwt.repository;

import com.example.sbbasicjwt.model.ERole;
import com.example.sbbasicjwt.model.Role;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for RoleRepository using @DataJpaTest to test the repository layer in isolation.
 */
@DataJpaTest
public class RoleRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private RoleRepository roleRepository;

    @Test
    public void testFindByName_WhenRoleExists_ShouldReturnRole() {
        // Arrange
        Role userRole = new Role(ERole.ROLE_USER);
        entityManager.persist(userRole);
        
        Role modRole = new Role(ERole.ROLE_MODERATOR);
        entityManager.persist(modRole);
        
        Role adminRole = new Role(ERole.ROLE_ADMIN);
        entityManager.persist(adminRole);
        
        entityManager.flush();

        // Act
        Optional<Role> foundUserRole = roleRepository.findByName(ERole.ROLE_USER);
        Optional<Role> foundModRole = roleRepository.findByName(ERole.ROLE_MODERATOR);
        Optional<Role> foundAdminRole = roleRepository.findByName(ERole.ROLE_ADMIN);

        // Assert
        assertThat(foundUserRole).isPresent();
        assertThat(foundUserRole.get().getName()).isEqualTo(ERole.ROLE_USER);
        
        assertThat(foundModRole).isPresent();
        assertThat(foundModRole.get().getName()).isEqualTo(ERole.ROLE_MODERATOR);
        
        assertThat(foundAdminRole).isPresent();
        assertThat(foundAdminRole.get().getName()).isEqualTo(ERole.ROLE_ADMIN);
    }

    @Test
    public void testFindByName_WhenRoleDoesNotExist_ShouldReturnEmpty() {
        // Arrange - database is empty

        // Act
        Optional<Role> foundRole = roleRepository.findByName(ERole.ROLE_USER);

        // Assert
        assertThat(foundRole).isEmpty();
    }
}