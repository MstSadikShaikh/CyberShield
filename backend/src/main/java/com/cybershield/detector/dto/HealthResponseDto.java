package com.cybershield.detector.dto;

import java.time.Instant;
import java.util.Map;

public class HealthResponseDto {

    private String status; // "UP", "DEGRADED", "DOWN"
    private Instant timestamp;
    private String modelStatus;
    private String modelName;
    private String modelVersion;
    private String publisherMetric;
    private String databaseStatus;
    private long uptimeSeconds;
    private Map<String, Object> details;

    public HealthResponseDto() {
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }

    public String getModelStatus() {
        return modelStatus;
    }

    public void setModelStatus(String modelStatus) {
        this.modelStatus = modelStatus;
    }

    public String getModelName() {
        return modelName;
    }

    public void setModelName(String modelName) {
        this.modelName = modelName;
    }

    public String getModelVersion() {
        return modelVersion;
    }

    public void setModelVersion(String modelVersion) {
        this.modelVersion = modelVersion;
    }

    public String getPublisherMetric() {
        return publisherMetric;
    }

    public void setPublisherMetric(String publisherMetric) {
        this.publisherMetric = publisherMetric;
    }

    public String getDatabaseStatus() {
        return databaseStatus;
    }

    public void setDatabaseStatus(String databaseStatus) {
        this.databaseStatus = databaseStatus;
    }

    public long getUptimeSeconds() {
        return uptimeSeconds;
    }

    public void setUptimeSeconds(long uptimeSeconds) {
        this.uptimeSeconds = uptimeSeconds;
    }

    public Map<String, Object> getDetails() {
        return details;
    }

    public void setDetails(Map<String, Object> details) {
        this.details = details;
    }
}
