package com.lintsec.repository;

import com.lintsec.domain.Scan;
import com.lintsec.domain.ScanStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Collection;
import java.util.Optional;

@Repository
public interface ScanRepository extends JpaRepository<Scan, Long> {

    Page<Scan> findByUserIdOrderByCreatedAtDesc(Long userId, Pageable pageable);

    Optional<Scan> findByIdAndUserId(Long id, Long userId);

    long countByUserIdAndStatus(Long userId, ScanStatus status);

    long countByUserId(Long userId);

    long countByUserIdAndStatusIn(Long userId, Collection<ScanStatus> statuses);

    /**
     * Bulk-transition scans left in the given statuses to {@code to}. Used at startup to clean up
     * RUNNING/PENDING scans whose worker thread died on the previous shutdown — otherwise they
     * stay RUNNING forever and can be neither deleted nor cancelled.
     */
    @Modifying
    @Transactional
    @Query("update Scan s set s.status = :to, s.completedAt = :now, s.errorMessage = :message "
            + "where s.status in :from")
    int reconcileStatuses(@Param("from") Collection<ScanStatus> from,
                          @Param("to") ScanStatus to,
                          @Param("now") Instant now,
                          @Param("message") String message);
}
