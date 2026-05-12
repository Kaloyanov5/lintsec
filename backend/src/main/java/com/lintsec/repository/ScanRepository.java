package com.lintsec.repository;

import com.lintsec.domain.Scan;
import com.lintsec.domain.ScanStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ScanRepository extends JpaRepository<Scan, Long> {

    Page<Scan> findByUserIdOrderByCreatedAtDesc(Long userId, Pageable pageable);

    Optional<Scan> findByIdAndUserId(Long id, Long userId);

    long countByUserIdAndStatus(Long userId, ScanStatus status);
}
