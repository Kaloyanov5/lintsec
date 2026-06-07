package com.lintsec.report;

import com.lintsec.domain.Severity;
import com.lintsec.dto.FindingGroupResponse;
import com.lintsec.dto.FindingInstanceResponse;
import com.lintsec.dto.ScanExport;
import com.lintsec.dto.ScanResponse;
import com.lowagie.text.Document;
import com.lowagie.text.DocumentException;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import org.springframework.stereotype.Component;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * Renders a {@link ScanExport} to a PDF report via OpenPDF. Layout is deliberately plain — correct
 * structure over styling. A render failure is fatal (unchecked) so the export endpoint returns 500
 * rather than serving a corrupt download.
 */
@Component
public class ScanReportPdfRenderer {

    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'").withZone(ZoneOffset.UTC);

    private static final Color INK = new Color(15, 23, 42);
    private static final Color MUTED = new Color(100, 116, 139);
    private static final Color RULE = new Color(226, 232, 240);

    private static final Font H1 = new Font(Font.HELVETICA, 20, Font.BOLD, INK);
    private static final Font H2 = new Font(Font.HELVETICA, 12, Font.BOLD, INK);
    private static final Font LABEL = new Font(Font.HELVETICA, 8, Font.BOLD, MUTED);
    private static final Font BODY = new Font(Font.HELVETICA, 10, Font.NORMAL, new Color(30, 41, 59));
    private static final Font META = new Font(Font.HELVETICA, 9, Font.NORMAL, MUTED);
    private static final Font MONO = new Font(Font.COURIER, 8, Font.NORMAL, new Color(51, 65, 85));

    public byte[] render(ScanExport export) {
        Document doc = new Document(PageSize.A4, 48, 48, 54, 54);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            PdfWriter.getInstance(doc, out);
            doc.open();
            writeHeader(doc, export);
            writeSummary(doc, export);
            writeGroups(doc, export);
            doc.close();
        } catch (DocumentException e) {
            throw new IllegalStateException("failed to render scan report PDF", e);
        }
        return out.toByteArray();
    }

    private void writeHeader(Document doc, ScanExport export) throws DocumentException {
        ScanResponse scan = export.scan();

        Paragraph title = new Paragraph("LintSec Scan Report", H1);
        title.setSpacingAfter(2);
        doc.add(title);

        Paragraph target = new Paragraph(scan.targetUrl(), META);
        target.setSpacingAfter(10);
        doc.add(target);

        doc.add(metaLine("Status", scan.status().name()));
        doc.add(metaLine("Pages crawled", String.valueOf(scan.pagesCrawled())));
        doc.add(metaLine("Started", fmt(scan.startedAt())));
        doc.add(metaLine("Completed", fmt(scan.completedAt())));
        doc.add(metaLine("Generated", TS.format(Instant.now())));

        Paragraph counts = new Paragraph(
                export.groups().size() + " distinct issue(s) across " + export.totalFindings() + " occurrence(s)",
                META);
        counts.setSpacingBefore(8);
        counts.setSpacingAfter(4);
        doc.add(counts);
    }

    private void writeSummary(Document doc, ScanExport export) throws DocumentException {
        PdfPTable table = new PdfPTable(Severity.values().length);
        table.setWidthPercentage(100);
        table.setSpacingBefore(6);
        table.setSpacingAfter(16);

        for (Severity sev : Severity.values()) {
            table.addCell(summaryCell(sev.name(), LABEL, Color.WHITE, severityColor(sev)));
        }
        for (Severity sev : Severity.values()) {
            int n = export.severityCounts().getOrDefault(sev, 0);
            Font cellFont = new Font(Font.HELVETICA, 14, Font.BOLD, n > 0 ? INK : MUTED);
            table.addCell(summaryCell(String.valueOf(n), cellFont, INK, Color.WHITE));
        }
        doc.add(table);
    }

    private void writeGroups(Document doc, ScanExport export) throws DocumentException {
        if (export.groups().isEmpty()) {
            doc.add(new Paragraph("No findings for this scan.", BODY));
            return;
        }
        for (FindingGroupResponse group : export.groups()) {
            writeGroup(doc, group);
        }
    }

    private void writeGroup(Document doc, FindingGroupResponse group) throws DocumentException {
        Paragraph heading = new Paragraph();
        heading.setSpacingBefore(12);
        heading.add(new Phrase(group.severity().name() + "  ",
                new Font(Font.HELVETICA, 11, Font.BOLD, severityColor(group.severity()))));
        heading.add(new Phrase(group.title(), H2));
        doc.add(heading);

        String subtitle = humanType(group.vulnerabilityType());
        if (group.count() > 1) subtitle += "  ·  " + group.count() + " occurrences";
        Paragraph sub = new Paragraph(subtitle, META);
        sub.setSpacingAfter(6);
        doc.add(sub);

        if (notBlank(group.description())) section(doc, "Description", group.description());
        if (notBlank(group.remediation())) section(doc, "Remediation", group.remediation());
        if (notBlank(group.aiExplanation())) section(doc, "AI explanation", group.aiExplanation());

        doc.add(label("Affected locations"));
        for (FindingInstanceResponse inst : group.instances()) {
            doc.add(new Paragraph(formatInstance(inst), MONO));
        }
    }

    private void section(Document doc, String title, String body) throws DocumentException {
        doc.add(label(title));
        Paragraph p = new Paragraph(body, BODY);
        p.setSpacingAfter(6);
        doc.add(p);
    }

    private Paragraph label(String text) {
        Paragraph p = new Paragraph(text.toUpperCase(), LABEL);
        p.setSpacingBefore(4);
        p.setSpacingAfter(2);
        return p;
    }

    private Paragraph metaLine(String label, String value) {
        Paragraph p = new Paragraph();
        p.add(new Phrase(label + ": ", new Font(Font.HELVETICA, 9, Font.BOLD, MUTED)));
        p.add(new Phrase(value, META));
        return p;
    }

    private static String formatInstance(FindingInstanceResponse inst) {
        StringBuilder sb = new StringBuilder("• ");
        sb.append(inst.url() != null ? inst.url() : "(no url)");
        if (notBlank(inst.parameter())) sb.append("  [param: ").append(inst.parameter()).append(']');
        if (notBlank(inst.note())) sb.append("  — ").append(inst.note());
        return sb.toString();
    }

    private static PdfPCell summaryCell(String text, Font font, Color textColor, Color bg) {
        Phrase phrase = new Phrase(text, font);
        PdfPCell cell = new PdfPCell(phrase);
        cell.setHorizontalAlignment(Element.ALIGN_CENTER);
        cell.setPadding(5);
        cell.setBackgroundColor(bg);
        cell.setBorderColor(RULE);
        return cell;
    }

    private static Color severityColor(Severity s) {
        return switch (s) {
            case CRITICAL -> new Color(185, 28, 28);
            case HIGH -> new Color(194, 65, 12);
            case MEDIUM -> new Color(180, 83, 9);
            case LOW -> new Color(2, 132, 199);
            case INFO -> new Color(71, 85, 105);
        };
    }

    private static String humanType(com.lintsec.domain.VulnerabilityType type) {
        return switch (type) {
            case XSS -> "Cross-Site Scripting";
            case SQL_INJECTION -> "SQL Injection";
            case CORS -> "CORS Misconfiguration";
            case SECURITY_HEADERS -> "Security Headers";
            case SENSITIVE_DATA -> "Sensitive Data";
            case OPEN_REDIRECT -> "Open Redirect";
            case COOKIE_SECURITY -> "Cookie Security";
            case CSRF -> "CSRF";
            case DIRECTORY_LISTING -> "Directory Listing";
            case INSECURE_HTTP_METHOD -> "Insecure HTTP Method";
            case PATH_TRAVERSAL -> "Path Traversal";
            case COMMAND_INJECTION -> "Command Injection";
            case MIXED_CONTENT -> "Mixed Content";
            case MISSING_SRI -> "Missing Subresource Integrity";
        };
    }

    private static String fmt(Instant instant) {
        return instant != null ? TS.format(instant) : "—";
    }

    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }
}
