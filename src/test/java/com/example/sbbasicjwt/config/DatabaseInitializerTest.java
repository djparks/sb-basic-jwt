package com.example.sbbasicjwt.config;

import com.example.sbbasicjwt.model.ERole;
import com.example.sbbasicjwt.model.Role;
import com.example.sbbasicjwt.repository.RoleRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

@SpringBootTest
public class DatabaseInitializerTest {

    @Autowired
    private DatabaseInitializer databaseInitializer;

    @MockBean
    private RoleRepository roleRepository;

    @Captor
    private ArgumentCaptor<List<Role>> rolesCaptor;

    @BeforeEach
    public void setup() {
        Mockito.reset(roleRepository);
    }

    @Test
    public void testRunWhenNoRolesExist() throws Exception {
        // Setup
        when(roleRepository.count()).thenReturn(0L);

        // Execute
        databaseInitializer.run("test");

        // Verify
        verify(roleRepository).count();
        verify(roleRepository).saveAll(rolesCaptor.capture());

        List<Role> savedRoles = rolesCaptor.getValue();
        assertEquals(3, savedRoles.size(), "Should save 3 roles");

        // Verify each role
        assertEquals(ERole.ROLE_USER, savedRoles.get(0).getName(), "First role should be USER");
        assertEquals(ERole.ROLE_MODERATOR, savedRoles.get(1).getName(), "Second role should be MODERATOR");
        assertEquals(ERole.ROLE_ADMIN, savedRoles.get(2).getName(), "Third role should be ADMIN");
    }

    @Test
    public void testRunWhenRolesAlreadyExist() throws Exception {
        // Setup
        when(roleRepository.count()).thenReturn(3L);

        // Execute
        databaseInitializer.run("test");

        // Verify
        verify(roleRepository).count();
        verify(roleRepository, never()).saveAll(any());
    }
}
