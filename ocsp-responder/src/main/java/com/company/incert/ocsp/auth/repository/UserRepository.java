package com.company.incert.ocsp.auth.repository;

import com.company.incert.ocsp.auth.entity.AuthSource;
import com.company.incert.ocsp.auth.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, String> {
    Optional<UserEntity> findByUsernameAndDeletedAtIsNull(String username);
    Optional<UserEntity> findByUsername(String username);
    Optional<UserEntity> findByExternalId(String externalId);
    Optional<UserEntity> findByEmailIgnoreCaseAndEmailVerifiedTrueAndDeletedAtIsNull(String email);
    List<UserEntity> findAllByDeletedAtIsNull();
    List<UserEntity> findAllByAuthSourceAndDeletedAtIsNull(AuthSource authSource);
    boolean existsByUsernameAndDeletedAtIsNull(String username);
}
