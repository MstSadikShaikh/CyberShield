package com.cybershield.detector.dto;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class ThreatIntelligenceDto {

    private String status; // "NO_MATCH", "MATCH_FOUND", "NOT_CONFIGURED", "UNAVAILABLE", "DISABLED", "ERROR"
    private String source; // e.g., "Google Web Risk API"
    private List<String> threatMatches = new ArrayList<>(); // e.g., ["SOCIAL_ENGINEERING", "MALWARE"]
    private String details;
    private Instant checkedAt = Instant.now();

    public ThreatIntelligenceDto() {
    }

    public ThreatIntelligenceDto(String status, String source, List<String> threatMatches, String details) {
        this.status = status;
        this.source = source;
        this.threatMatches = threatMatches != null ? threatMatches : new ArrayList<>();
        this.details = details;
        this.checkedAt = Instant.now();
    }

    public static ThreatIntelligenceDto notConfigured(String source) {
        return new ThreatIntelligenceDto(
                "NOT_CONFIGURED",
                source,
                new ArrayList<>(),
                "Threat intelligence lookup is not enabled or API credentials are not configured."
        );
    }

    public static ThreatIntelligenceDto unavailable(String source, String reason) {
        return new ThreatIntelligenceDto(
                "UNAVAILABLE",
                source,
                new ArrayList<>(),
                reason
        );
    }

    public static ThreatIntelligenceDto noMatch(String source) {
        return new ThreatIntelligenceDto(
                "NO_MATCH",
                source,
                new ArrayList<>(),
                "No active threat signature recorded in threat feed. (Note: does not guarantee the URL is safe)."
        );
    }

    public static ThreatIntelligenceDto matchFound(String source, List<String> threats) {
        return new ThreatIntelligenceDto(
                "MATCH_FOUND",
                source,
                threats,
                "URL matches known threat signatures: " + String.join(", ", threats)
        );
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public List<String> getThreatMatches() {
        return threatMatches;
    }

    public void setThreatMatches(List<String> threatMatches) {
        this.threatMatches = threatMatches;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    public Instant getCheckedAt() {
        return checkedAt;
    }

    public void setCheckedAt(Instant checkedAt) {
        this.checkedAt = checkedAt;
    }
}
