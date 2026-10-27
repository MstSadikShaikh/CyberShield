package com.cybershield.detector.service;

import com.cybershield.detector.dto.ThreatIntelligenceDto;

public interface ThreatIntelligenceService {

    /**
     * Queries the configured threat intelligence provider for known malware,
     * social engineering, or unwanted software signatures associated with the URL.
     * Note: A clean result (NO_MATCH) indicates no active signature, not absolute safety.
     *
     * @param url the normalized URL to check
     * @return ThreatIntelligenceDto containing status, threat matches, and source
     */
    ThreatIntelligenceDto checkUrl(String url);

    /**
     * Returns the name of the threat intelligence provider (e.g., "Google Web Risk API").
     */
    String getProviderName();

    /**
     * Checks whether the service is actively enabled with valid credentials.
     */
    boolean isConfigured();
}
