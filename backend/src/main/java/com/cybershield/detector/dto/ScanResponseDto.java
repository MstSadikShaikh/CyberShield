package com.cybershield.detector.dto;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class ScanResponseDto {

    private Long id;
    private String submittedUrl;
    private String sanitizedUrl;
    private String prediction; // "PHISHING", "LEGITIMATE", "UNCERTAIN"
    private Double riskScore; // 0.0 - 100.0
    private String riskLevel; // "LOW", "MEDIUM", "HIGH", "CRITICAL"
    private String modelVersion;
    private Double modelProbability; // raw probability from pretrained model
    private String modelAssessment; // e.g. "PHISHING (62.3%)" or "LEGITIMATE (12.1%)"
    private String finalAssessment; // "CONFIRMED_THREAT", "HIGH_RISK_ML", "CONFLICT_RESOLVED_BENIGN", etc.
    private String explanation;
    private List<String> precautions = new ArrayList<>();
    private List<UrlIndicatorDto> indicators = new ArrayList<>();
    private List<String> limitations = new ArrayList<>();
    private ThreatIntelligenceDto threatIntelligence;
    private GeminiAnalysisDto geminiAnalysis;
    private Instant scannedAt;

    public ScanResponseDto() {
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

    public String getModelAssessment() {
        return modelAssessment;
    }

    public void setModelAssessment(String modelAssessment) {
        this.modelAssessment = modelAssessment;
    }

    public String getFinalAssessment() {
        return finalAssessment;
    }

    public void setFinalAssessment(String finalAssessment) {
        this.finalAssessment = finalAssessment;
    }

    public String getExplanation() {
        return explanation;
    }

    public void setExplanation(String explanation) {
        this.explanation = explanation;
    }

    public List<String> getPrecautions() {
        return precautions;
    }

    public void setPrecautions(List<String> precautions) {
        this.precautions = precautions;
    }

    public List<UrlIndicatorDto> getIndicators() {
        return indicators;
    }

    public void setIndicators(List<UrlIndicatorDto> indicators) {
        this.indicators = indicators;
    }

    public List<String> getLimitations() {
        return limitations;
    }

    public void setLimitations(List<String> limitations) {
        this.limitations = limitations;
    }

    public ThreatIntelligenceDto getThreatIntelligence() {
        return threatIntelligence;
    }

    public void setThreatIntelligence(ThreatIntelligenceDto threatIntelligence) {
        this.threatIntelligence = threatIntelligence;
    }

    public GeminiAnalysisDto getGeminiAnalysis() {
        return geminiAnalysis;
    }

    public void setGeminiAnalysis(GeminiAnalysisDto geminiAnalysis) {
        this.geminiAnalysis = geminiAnalysis;
    }

    public Instant getScannedAt() {
        return scannedAt;
    }

    public void setScannedAt(Instant scannedAt) {
        this.scannedAt = scannedAt;
    }
}
