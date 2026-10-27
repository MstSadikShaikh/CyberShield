package com.cybershield.detector.service;

import com.cybershield.detector.dto.ThreatIntelligenceDto;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Service
public class GoogleWebRiskThreatService implements ThreatIntelligenceService {

    private static final Logger log = LoggerFactory.getLogger(GoogleWebRiskThreatService.class);
    public static final String PROVIDER_NAME = "Google Web Risk API";

    private final UrlValidatorService urlValidatorService;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;

    @Value("${cybershield.threat-intel.enabled:false}")
    private boolean enabled = false;

    @Value("${cybershield.threat-intel.api-key:}")
    private String apiKey = "";

    @Value("${cybershield.threat-intel.timeout-seconds:4}")
    private int timeoutSeconds = 4;

    @Value("${cybershield.threat-intel.base-url:https://webrisk.googleapis.com}")
    private String baseUrl = "https://webrisk.googleapis.com";

    @org.springframework.beans.factory.annotation.Autowired
    public GoogleWebRiskThreatService(UrlValidatorService urlValidatorService, ObjectMapper objectMapper) {
        this(urlValidatorService, objectMapper, HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(4))
                .build());
    }

    public GoogleWebRiskThreatService(UrlValidatorService urlValidatorService,
                                     ObjectMapper objectMapper,
                                     HttpClient httpClient) {
        this.urlValidatorService = urlValidatorService;
        this.objectMapper = objectMapper;
        this.httpClient = httpClient;
    }

    @Override
    public ThreatIntelligenceDto checkUrl(String url) {
        if (!isConfigured()) {
            return ThreatIntelligenceDto.notConfigured(PROVIDER_NAME);
        }

        // Strictly strip query string and fragment to prevent sending sensitive credentials or tokens
        String sanitizedTarget = urlValidatorService.stripQueryAndFragment(url);
        if (sanitizedTarget.isBlank()) {
            return ThreatIntelligenceDto.unavailable(PROVIDER_NAME, "Invalid target URL for threat check.");
        }

        try {
            String encodedUri = URLEncoder.encode(sanitizedTarget, StandardCharsets.UTF_8);
            String requestUrl = String.format(
                    "%s/v1/uris:search?threatTypes=MALWARE&threatTypes=SOCIAL_ENGINEERING&threatTypes=UNWANTED_SOFTWARE&uri=%s&key=%s",
                    baseUrl, encodedUri, apiKey
            );

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(requestUrl))
                    .timeout(Duration.ofSeconds(Math.max(1, timeoutSeconds)))
                    .header("Accept", "application/json")
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            int statusCode = response.statusCode();

            if (statusCode == 200) {
                String body = response.body();
                JsonNode root = objectMapper.readTree(body != null && !body.isBlank() ? body : "{}");
                JsonNode threatNode = root.path("threat");

                if (threatNode.isMissingNode() || threatNode.isNull() || !threatNode.has("threatTypes")) {
                    return ThreatIntelligenceDto.noMatch(PROVIDER_NAME);
                }

                List<String> threats = new ArrayList<>();
                JsonNode threatTypes = threatNode.path("threatTypes");
                if (threatTypes.isArray()) {
                    for (JsonNode t : threatTypes) {
                        threats.add(t.asText());
                    }
                }

                if (threats.isEmpty()) {
                    return ThreatIntelligenceDto.noMatch(PROVIDER_NAME);
                }

                log.info("Threat match detected by {} for domain: {}", PROVIDER_NAME, urlValidatorService.extractHost(sanitizedTarget));
                return ThreatIntelligenceDto.matchFound(PROVIDER_NAME, threats);

            } else if (statusCode == 429) {
                log.warn("{} rate limit or quota exceeded (HTTP 429).", PROVIDER_NAME);
                return ThreatIntelligenceDto.unavailable(PROVIDER_NAME, "Threat intelligence provider quota exceeded or rate limited.");
            } else if (statusCode == 400 || statusCode == 403) {
                log.warn("{} request failed with HTTP {} (check configuration or permissions).", PROVIDER_NAME, statusCode);
                return ThreatIntelligenceDto.unavailable(PROVIDER_NAME, "Threat intelligence API rejected request (HTTP " + statusCode + ").");
            } else {
                log.warn("{} responded with unexpected HTTP {}.", PROVIDER_NAME, statusCode);
                return ThreatIntelligenceDto.unavailable(PROVIDER_NAME, "Threat intelligence provider returned HTTP " + statusCode + ".");
            }

        } catch (HttpTimeoutException e) {
            log.warn("{} lookup timed out after {}s.", PROVIDER_NAME, timeoutSeconds);
            return ThreatIntelligenceDto.unavailable(PROVIDER_NAME, "Threat intelligence lookup timed out after " + timeoutSeconds + "s.");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("{} request interrupted.", PROVIDER_NAME);
            return ThreatIntelligenceDto.unavailable(PROVIDER_NAME, "Threat intelligence request interrupted.");
        } catch (Exception e) {
            log.warn("{} query failed: {}", PROVIDER_NAME, e.getMessage());
            return ThreatIntelligenceDto.unavailable(PROVIDER_NAME, "Threat intelligence lookup encountered an error.");
        }
    }

    @Override
    public String getProviderName() {
        return PROVIDER_NAME;
    }

    @Override
    public boolean isConfigured() {
        return enabled && apiKey != null && !apiKey.trim().isEmpty() && !apiKey.contains("YOUR_");
    }

    // Setters for testability
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public void setTimeoutSeconds(int timeoutSeconds) {
        this.timeoutSeconds = timeoutSeconds;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }
}
