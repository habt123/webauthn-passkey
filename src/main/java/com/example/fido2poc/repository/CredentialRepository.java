package com.example.fido2poc.repository;

import com.example.fido2poc.model.CredentialEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface CredentialRepository extends JpaRepository<CredentialEntity, Long> {

    List<CredentialEntity> findByUserId(Long userId);

    Optional<CredentialEntity> findByCredentialId(String credentialId);
}
