package com.cybershield.detector.dto;

import java.util.ArrayList;
import java.util.List;

public class GeminiAnalysisDto {

    private String status; // "SUCCESS", "NOT_CONFIGURED", "DISABLED", "SKIPPED", "UNAVAILABLE", "ERROR"
    private String assessment; // "SUSPICIOUS", "NOT_OBVIOUSLY_SUSPICIOUS", "INSUFFICIENT_EVIDENCE", "NOT_PERFORMED"
    private List<String> indicators = new ArrayList<>();
    private String explanation;
    private List<String> limitations = new ArrayList<>();
    private String providerModel;

    public GeminiAnalysisDto() {
    }

    public GeminiAnalysisDto(String status, String assessment, List<String> indicators,
                             String explanation, List<String> limitations, String providerModel) {
        this.status = status;
        this.assessment = assessment;
        this.indicators = indicators != null ? indicators : new ArrayList<>();
        this.explanation = explanation;
        this.limitations = limitations != null ? limitations : new ArrayList<>();
        this.providerModel = providerModel != null ? providerModel : "gemini-3.8-flash";
    }

    public static GeminiAnalysisDto notConfigured(String model) {
        return new GeminiAnalysisDto(
                "NOT_CONFIGURED",
                "NOT_PERFORMED",
                new ArrayList<>(),
                "Gemini secondary analysis is not enabled or GEMINI_API_KEY is not configured.",
                List.of("Secondary AI analysis disabled; relying on local ML model and heuristics."),
                model
        );
    }

    public static GeminiAnalysisDto skipped(String model, String reason) {
        return new GeminiAnalysisDto(
                "SKIPPED",
                "NOT_PERFORMED",
                new ArrayList<>(),
                reason,
                List.of("Gemini analysis is invoked conditionally on uncertain ML results or evidence conflicts to conserve quota."),
                model
        );
    }

    public static GeminiAnalysisDto unavailable(String model, String reason) {
        return new GeminiAnalysisDto(
                "UNAVAILABLE",
                "NOT_PERFORMED",
                new ArrayList<>(),
                reason,
                List.of("Remote API request failed; falling back to local detection components."),
                model
        );
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getAssessment() {
        return assessment;
    }

    public void setAssessment(String assessment) {
        this.assessment = assessment;
    }

    public List<String> getIndicators() {
        return indicators;
    }

    public void setIndicators(List<String> indicators) {
        this.indicators = indicators;
    }

    public String getExplanation() {
        return explanation;
    }

    public void setExplanation(String explanation) {
        this.explanation = explanation;
    }

    public List<String> getLimitations() {
        return limitations;
    }

    public void setLimitations(List<String> limitations) {
        this.limitations = limitations;
    }

    public String getProviderModel() {
        return providerModel;
    }

    public void setProviderModel(String providerModel) {
        this.providerModel = providerModel;
    }
}
