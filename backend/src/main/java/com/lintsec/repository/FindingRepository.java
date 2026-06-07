package com.lintsec.repository;

import com.lintsec.domain.Finding;
import com.lintsec.domain.Severity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

@Repository
public interface FindingRepository extends JpaRepository<Finding, Long> {

    List<Finding> findByScanIdOrderBySeverityAscCreatedAtAsc(Long scanId);

    long countByScanId(Long scanId);

    long countByScanIdAndSeverity(Long scanId, Severity severity);

    @Query("select f.severity, count(f) from Finding f where f.scan.user.id = :userId group by f.severity")
    List<Object[]> countBySeverityForUser(@Param("userId") Long userId);
}
