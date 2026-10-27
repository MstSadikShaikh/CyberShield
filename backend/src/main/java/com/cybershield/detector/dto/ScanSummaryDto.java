package com.cybershield.detector.dto;

import java.time.Instant;

public class ScanSummaryDto {

    private Long id;
    private String submittedUrl;
    private String prediction;
    private Double riskScore;
    private String riskLevel;
    private Instant scannedAt;

    public ScanSummaryDto() {
    }

    public ScanSummaryDto(Long id, String submittedUrl, String prediction, Double riskScore, String riskLevel, Instant scannedAt) {
        this.id = id;
        this.submittedUrl = submittedUrl;
        this.prediction = prediction;
        this.riskScore = riskScore;
        this.riskLevel = riskLevel;
        this.scannedAt = scannedAt;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getSubmittedUrl() {
        return submittedUrl;
    }

    public void setSubmittedUrl(String submittedUrl) {
        this.submittedUrl = submittedUrl;
    }

    public String getPrediction() {
        return prediction;
    }

    public void setPrediction(String prediction) {
        this.prediction = prediction;
    }

    public Double getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(Double riskScore) {
        this.riskScore = riskScore;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public Instant getScannedAt() {
        return scannedAt;
    }

    public void setScannedAt(Instant scannedAt) {
        this.scannedAt = scannedAt;
    }
}
