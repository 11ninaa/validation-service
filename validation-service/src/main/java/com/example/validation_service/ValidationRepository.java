package com.example.validation_service;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface ValidationRepository extends JpaRepository<ValidationLog, Long> {
    List<ValidationLog> findAllByOrderByValidationTimeDesc();
}