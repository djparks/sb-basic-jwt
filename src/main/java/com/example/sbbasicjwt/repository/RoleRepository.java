package com.example.sbbasicjwt.repository;

import com.example.sbbasicjwt.model.ERole;
import com.example.sbbasicjwt.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository interface for Role entity.
 */
@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
    /**
     * Find a role by its name.
     *
     * @param name the role name to search for
     * @return an Optional containing the role if found, or empty if not found
     */
    Optional<Role> findByName(ERole name);
}