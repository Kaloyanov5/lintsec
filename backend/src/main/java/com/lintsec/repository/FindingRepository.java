package com.lintsec.repository;

import com.lintsec.domain.Finding;
import com.lintsec.domain.Severity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FindingRepository extends JpaRepository<Finding, Long> {

    List<Finding> findByScanIdOrderBySeverityAscCreatedAtAsc(Long scanId);

    long countByScanId(Long scanId);

    long countByScanIdAndSeverity(Long scanId, Severity severity);
}
