package com.cybershield.detector;

import com.cybershield.detector.dto.ThreatIntelligenceDto;
import com.cybershield.detector.service.GoogleWebRiskThreatService;
import com.cybershield.detector.service.UrlValidatorService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class ThreatIntelligenceServiceTest {

    private GoogleWebRiskThreatService threatService;
    private UrlValidatorService urlValidatorService;
    private ObjectMapper objectMapper;

    @Mock
    private HttpClient mockHttpClient;

    @BeforeEach
    public void setUp() {
        urlValidatorService = new UrlValidatorService();
        objectMapper = new ObjectMapper();
        threatService = new GoogleWebRiskThreatService(urlValidatorService, objectMapper, mockHttpClient);
    }

    @Test
    public void testDisabledConfigurationReturnsNotConfigured() {
        threatService.setEnabled(false);
        threatService.setApiKey("webrisk-key-123");

        ThreatIntelligenceDto result = threatService.checkUrl("https://example.com");

        assertEquals("NOT_CONFIGURED", result.getStatus());
        assertEquals("Google Web Risk API", result.getSource());
        assertTrue(result.getThreatMatches().isEmpty());
        assertFalse(result.getDetails().contains("webrisk-key-123"));
    }

    @Test
    public void testMissingApiKeyReturnsNotConfigured() {
        threatService.setEnabled(true);
        threatService.setApiKey("");

        ThreatIntelligenceDto result = threatService.checkUrl("https://example.com");

        assertEquals("NOT_CONFIGURED", result.getStatus());
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testConfirmedThreatMatch() throws Exception {
        threatService.setEnabled(true);
        threatService.setApiKey("valid-webrisk-key");

        String matchJson = """
                {
                  "threat": {
                    "threatTypes": ["SOCIAL_ENGINEERING", "MALWARE"],
                    "expireTime": "2026-10-27T15:00:00Z"
                  }
                }
                """;

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(matchJson);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        ThreatIntelligenceDto result = threatService.checkUrl("https://malicious-phish-domain.com/login");

        assertEquals("MATCH_FOUND", result.getStatus());
        assertEquals(2, result.getThreatMatches().size());
        assertTrue(result.getThreatMatches().contains("SOCIAL_ENGINEERING"));
        assertTrue(result.getThreatMatches().contains("MALWARE"));
        assertTrue(result.getDetails().contains("matches known threat signatures"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testNoMatchDoesNotClaimSafety() throws Exception {
        threatService.setEnabled(true);
        threatService.setApiKey("valid-webrisk-key");

        // Clean response from Web Risk API is an empty JSON object
        String cleanJson = "{}";

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(cleanJson);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        ThreatIntelligenceDto result = threatService.checkUrl("https://chatgpt.com");

        assertEquals("NO_MATCH", result.getStatus());
        assertTrue(result.getThreatMatches().isEmpty());
        // Verify response clearly reminds that no-match is not proof of safety
        assertTrue(result.getDetails().contains("does not guarantee"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testQuotaOrRateLimitReturnsUnavailable() throws Exception {
        threatService.setEnabled(true);
        threatService.setApiKey("valid-webrisk-key");

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(429);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        ThreatIntelligenceDto result = threatService.checkUrl("https://example.com");

        assertEquals("UNAVAILABLE", result.getStatus());
        assertTrue(result.getDetails().contains("quota") || result.getDetails().contains("rate limited"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testTimeoutReturnsUnavailable() throws Exception {
        threatService.setEnabled(true);
        threatService.setApiKey("valid-webrisk-key");

        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new HttpTimeoutException("Connection timed out"));

        ThreatIntelligenceDto result = threatService.checkUrl("https://example.com");

        assertEquals("UNAVAILABLE", result.getStatus());
        assertTrue(result.getDetails().contains("timed out"));
    }
}
