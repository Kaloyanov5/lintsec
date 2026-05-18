package com.lintsec.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;

@Entity
@Table(
        name = "findings",
        indexes = {
                @Index(name = "idx_findings_scan", columnList = "scan_id"),
                @Index(name = "idx_findings_scan_severity", columnList = "scan_id, severity")
        }
)
@Getter
@Setter
@NoArgsConstructor
public class Finding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "scan_id", nullable = false, foreignKey = @ForeignKey(name = "fk_findings_scan"))
    private Scan scan;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_page_id", foreignKey = @ForeignKey(name = "fk_findings_scan_page"))
    private ScanPage scanPage;

    @Enumerated(EnumType.STRING)
    @Column(name = "vulnerability_type", nullable = false, length = 32)
    private VulnerabilityType vulnerabilityType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private Severity severity;

    @Column(nullable = false, length = 200)
    private String title;

    @Column(length = 2000)
    private String description;

    @Column(length = 4000)
    private String remediation;

    @Column(name = "evidence_json", columnDefinition = "TEXT")
    private String evidenceJson;

    @Column(name = "payload_ref", length = 64)
    private String payloadRef;

    @Column(name = "ai_explanation", columnDefinition = "TEXT")
    private String aiExplanation;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
}
