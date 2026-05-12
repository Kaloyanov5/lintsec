package com.lintsec.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
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
        name = "scan_pages",
        indexes = {
                @Index(name = "idx_scan_pages_scan", columnList = "scan_id")
        }
)
@Getter
@Setter
@NoArgsConstructor
public class ScanPage {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "scan_id", nullable = false, foreignKey = @ForeignKey(name = "fk_scan_pages_scan"))
    private Scan scan;

    @Column(nullable = false, length = 2048)
    private String url;

    @Column(name = "status_code")
    private Integer statusCode;

    @Column(nullable = false)
    private int depth;

    @Column(length = 500)
    private String title;

    @CreationTimestamp
    @Column(name = "crawled_at", nullable = false, updatable = false)
    private Instant crawledAt;
}
