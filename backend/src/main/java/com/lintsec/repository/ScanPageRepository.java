package com.lintsec.repository;

import com.lintsec.domain.ScanPage;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Repository
public interface ScanPageRepository extends JpaRepository<ScanPage, Long> {

    List<ScanPage> findByScanIdOrderByCrawledAtAsc(Long scanId);

    long countByScanId(Long scanId);

    @Modifying
    @Transactional
    @Query("delete from ScanPage p where p.scan.id = :scanId")
    void deleteByScanId(@Param("scanId") Long scanId);
}
