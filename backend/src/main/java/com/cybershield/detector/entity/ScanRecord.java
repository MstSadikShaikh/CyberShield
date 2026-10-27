package com.cybershield.detector.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "scan_history", indexes = {
        @Index(name = "idx_scanned_at", columnList = "scanned_at DESC"),
        @Index(name = "idx_prediction", columnList = "prediction"),
        @Index(name = "idx_risk_level", columnList = "risk_level"),
        @Index(name = "idx_final_assessment", columnList = "final_assessment")
})
public class ScanRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "submitted_url", nullable = false, length = 2048)
    private String submittedUrl;

    @Column(name = "sanitized_url", nullable = false, length = 2048)
    private String sanitizedUrl;

    @Column(nullable = false, length = 20)
    private String prediction;

    @Column(name = "risk_score", nullable = false)
    private Double riskScore;

    @Column(name = "risk_level", nullable = false, length = 20)
    private String riskLevel;

    @Column(name = "model_version", nullable = false, length = 100)
    private String modelVersion;

    @Column(name = "model_probability")
    private Double modelProbability;

    @Column(columnDefinition = "TEXT")
    private String explanation;

    @Column(name = "indicators_json", columnDefinition = "TEXT")
    private String indicatorsJson;

    @Column(name = "precautions_json", columnDefinition = "TEXT")
    private String precautionsJson;

    @Column(name = "scanned_at", nullable = false)
    private Instant scannedAt = Instant.now();

    // Hybrid Detection Fields
    @Column(name = "threat_intel_status", length = 50)
    private String threatIntelStatus = "NOT_CONFIGURED";

    @Column(name = "threat_intel_source", length = 100)
    private String threatIntelSource;

    @Column(name = "threat_categories_json", columnDefinition = "TEXT")
    private String threatCategoriesJson;

    @Column(name = "gemini_status", length = 50)
    private String geminiStatus = "NOT_CONFIGURED";

    @Column(name = "gemini_model", length = 100)
    private String geminiModel;

    @Column(name = "gemini_assessment_json", columnDefinition = "TEXT")
    private String geminiAssessmentJson;

    @Column(name = "final_assessment", length = 50)
    private String finalAssessment;

    public ScanRecord() {
    }

    public ScanRecord(String submittedUrl, String sanitizedUrl, String prediction, Double riskScore,
                      String riskLevel, String modelVersion, Double modelProbability, String explanation,
                      String indicatorsJson, String precautionsJson) {
        this.submittedUrl = submittedUrl;
        this.sanitizedUrl = sanitizedUrl;
        this.prediction = prediction;
        this.riskScore = riskScore;
        this.riskLevel = riskLevel;
        this.modelVersion = modelVersion;
        this.modelProbability = modelProbability;
        this.explanation = explanation;
        this.indicatorsJson = indicatorsJson;
        this.precautionsJson = precautionsJson;
        this.scannedAt = Instant.now();
    }

    // Getters and Setters
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

    public String getSanitizedUrl() {
        return sanitizedUrl;
    }

    public void setSanitizedUrl(String sanitizedUrl) {
        this.sanitizedUrl = sanitizedUrl;
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

    public String getModelVersion() {
        return modelVersion;
    }

    public void setModelVersion(String modelVersion) {
        this.modelVersion = modelVersion;
    }

    public Double getModelProbability() {
        return modelProbability;
    }

    public void setModelProbability(Double modelProbability) {
        this.modelProbability = modelProbability;
    }

    public String getExplanation() {
        return explanation;
    }

    public void setExplanation(String explanation) {
        this.explanation = explanation;
    }

    public String getIndicatorsJson() {
        return indicatorsJson;
    }

    public void setIndicatorsJson(String indicatorsJson) {
        this.indicatorsJson = indicatorsJson;
    }

    public String getPrecautionsJson() {
        return precautionsJson;
    }

    public void setPrecautionsJson(String precautionsJson) {
        this.precautionsJson = precautionsJson;
    }

    public Instant getScannedAt() {
        return scannedAt;
    }

    public void setScannedAt(Instant scannedAt) {
        this.scannedAt = scannedAt;
    }

    public String getThreatIntelStatus() {
        return threatIntelStatus;
    }

    public void setThreatIntelStatus(String threatIntelStatus) {
        this.threatIntelStatus = threatIntelStatus;
    }

    public String getThreatIntelSource() {
        return threatIntelSource;
    }

    public void setThreatIntelSource(String threatIntelSource) {
        this.threatIntelSource = threatIntelSource;
    }

    public String getThreatCategoriesJson() {
        return threatCategoriesJson;
    }

    public void setThreatCategoriesJson(String threatCategoriesJson) {
        this.threatCategoriesJson = threatCategoriesJson;
    }

    public String getGeminiStatus() {
        return geminiStatus;
    }

    public void setGeminiStatus(String geminiStatus) {
        this.geminiStatus = geminiStatus;
    }

    public String getGeminiModel() {
        return geminiModel;
    }

    public void setGeminiModel(String geminiModel) {
        this.geminiModel = geminiModel;
    }

    public String getGeminiAssessmentJson() {
        return geminiAssessmentJson;
    }

    public void setGeminiAssessmentJson(String geminiAssessmentJson) {
        this.geminiAssessmentJson = geminiAssessmentJson;
    }

    public String getFinalAssessment() {
        return finalAssessment;
    }

    public void setFinalAssessment(String finalAssessment) {
        this.finalAssessment = finalAssessment;
    }
}
