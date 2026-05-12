package com.lintsec.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;

@Entity
@Table(
        name = "scans",
        indexes = {
                @Index(name = "idx_scans_user_created_at", columnList = "user_id, created_at"),
                @Index(name = "idx_scans_status", columnList = "status")
        }
)
@Getter
@Setter
@NoArgsConstructor
public class Scan {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, foreignKey = @jakarta.persistence.ForeignKey(name = "fk_scans_user"))
    private User user;

    @Column(name = "target_url", nullable = false, length = 2048)
    private String targetUrl;

    @Column(name = "ownership_confirmed", nullable = false)
    private boolean ownershipConfirmed = false;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private ScanStatus status = ScanStatus.PENDING;

    @Column(name = "error_message", length = 1000)
    private String errorMessage;

    @Column(name = "pages_crawled", nullable = false)
    private int pagesCrawled = 0;

    @Column(name = "max_depth", nullable = false)
    private int maxDepth;

    @Column(name = "max_pages", nullable = false)
    private int maxPages;

    @Column(name = "request_delay_ms", nullable = false)
    private int requestDelayMs;

    @Column(name = "started_at")
    private Instant startedAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
}
