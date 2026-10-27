package com.cybershield.detector.dto;

public class UrlIndicatorDto {

    private String name;
    private String value;
    private String severity; // "SAFE", "INFO", "WARNING", "DANGER"
    private String description;

    public UrlIndicatorDto() {
    }

    public UrlIndicatorDto(String name, String value, String severity, String description) {
        this.name = name;
        this.value = value;
        this.severity = severity;
        this.description = description;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
