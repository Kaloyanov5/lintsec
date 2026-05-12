package com.lintsec.repository;

import com.lintsec.domain.ScanPage;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ScanPageRepository extends JpaRepository<ScanPage, Long> {

    List<ScanPage> findByScanIdOrderByCrawledAtAsc(Long scanId);

    long countByScanId(Long scanId);
}
