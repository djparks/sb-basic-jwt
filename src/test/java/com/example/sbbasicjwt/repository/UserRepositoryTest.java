package com.example.sbbasicjwt.repository;

import com.example.sbbasicjwt.model.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for UserRepository using @DataJpaTest to test the repository layer in isolation.
 */
@DataJpaTest
public class UserRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private UserRepository userRepository;

    @Test
    public void testFindByUsername_WhenUserExists_ShouldReturnUser() {
        // Arrange
        User user = new User("testuser", "test@example.com", "password");
        entityManager.persist(user);
        entityManager.flush();

        // Act
        Optional<User> found = userRepository.findByUsername("testuser");

        // Assert
        assertThat(found).isPresent();
        assertThat(found.get().getUsername()).isEqualTo("testuser");
        assertThat(found.get().getEmail()).isEqualTo("test@example.com");
    }

    @Test
    public void testFindByUsername_WhenUserDoesNotExist_ShouldReturnEmpty() {
        // Act
        Optional<User> found = userRepository.findByUsername("nonexistentuser");

        // Assert
        assertThat(found).isEmpty();
    }

    @Test
    public void testExistsByUsername_WhenUserExists_ShouldReturnTrue() {
        // Arrange
        User user = new User("testuser", "test@example.com", "password");
        entityManager.persist(user);
        entityManager.flush();

        // Act
        boolean exists = userRepository.existsByUsername("testuser");

        // Assert
        assertThat(exists).isTrue();
    }

    @Test
    public void testExistsByUsername_WhenUserDoesNotExist_ShouldReturnFalse() {
        // Act
        boolean exists = userRepository.existsByUsername("nonexistentuser");

        // Assert
        assertThat(exists).isFalse();
    }

    @Test
    public void testExistsByEmail_WhenUserExists_ShouldReturnTrue() {
        // Arrange
        User user = new User("testuser", "test@example.com", "password");
        entityManager.persist(user);
        entityManager.flush();

        // Act
        boolean exists = userRepository.existsByEmail("test@example.com");

        // Assert
        assertThat(exists).isTrue();
    }

    @Test
    public void testExistsByEmail_WhenUserDoesNotExist_ShouldReturnFalse() {
        // Act
        boolean exists = userRepository.existsByEmail("nonexistent@example.com");

        // Assert
        assertThat(exists).isFalse();
    }
}