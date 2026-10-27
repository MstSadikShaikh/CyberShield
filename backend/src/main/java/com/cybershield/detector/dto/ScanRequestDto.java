package com.cybershield.detector.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class ScanRequestDto {

    @NotBlank(message = "URL cannot be empty")
    @Size(max = 2048, message = "URL length exceeds maximum limit of 2048 characters")
    private String url;

    public ScanRequestDto() {
    }

    public ScanRequestDto(String url) {
        this.url = url;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}
