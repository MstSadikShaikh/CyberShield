package com.cybershield.detector;

import com.cybershield.detector.dto.GeminiAnalysisDto;
import com.cybershield.detector.dto.UrlIndicatorDto;
import com.cybershield.detector.service.GeminiAnalysisService;
import com.cybershield.detector.service.ModelInferenceResult;
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
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class GeminiAnalysisServiceTest {

    private GeminiAnalysisService geminiService;
    private UrlValidatorService urlValidatorService;
    private ObjectMapper objectMapper;

    @Mock
    private HttpClient mockHttpClient;

    @BeforeEach
    public void setUp() {
        urlValidatorService = new UrlValidatorService();
        objectMapper = new ObjectMapper();
        geminiService = new GeminiAnalysisService(urlValidatorService, objectMapper, mockHttpClient);
        geminiService.setModel("gemini-3.8-flash");
    }

    @Test
    public void testDisabledConfigurationReturnsNotConfigured() {
        geminiService.setEnabled(false);
        geminiService.setApiKey("test-key-123");

        GeminiAnalysisDto result = geminiService.analyzeUrl("https://example.com", null, Collections.emptyList());

        assertEquals("NOT_CONFIGURED", result.getStatus());
        assertEquals("NOT_PERFORMED", result.getAssessment());
        assertFalse(result.getExplanation().contains("test-key-123"));
    }

    @Test
    public void testMissingApiKeyReturnsNotConfigured() {
        geminiService.setEnabled(true);
        geminiService.setApiKey("");

        GeminiAnalysisDto result = geminiService.analyzeUrl("https://example.com", null, Collections.emptyList());

        assertEquals("NOT_CONFIGURED", result.getStatus());
        assertEquals("NOT_PERFORMED", result.getAssessment());
    }

    @Test
    public void testPlaceholderApiKeyReturnsNotConfigured() {
        geminiService.setEnabled(true);
        geminiService.setApiKey("YOUR_GEMINI_API_KEY");

        GeminiAnalysisDto result = geminiService.analyzeUrl("https://example.com", null, Collections.emptyList());

        assertEquals("NOT_CONFIGURED", result.getStatus());
        assertEquals("NOT_PERFORMED", result.getAssessment());
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testSuccessfulStructuredResponseParsing() throws Exception {
        geminiService.setEnabled(true);
        geminiService.setApiKey("valid-secret-key");

        String fakeGeminiBody = """
                {
                  "candidates": [
                    {
                      "content": {
                        "parts": [
                          {
                            "text": "{\\"assessment\\": \\"NOT_OBVIOUSLY_SUSPICIOUS\\", \\"indicators\\": [\\"Clean domain structure\\", \\"Standard TLD\\"], \\"explanation\\": \\"No deceptive indicators observed in the domain name.\\", \\"limitations\\": [\\"Passive check only\\"]}"
                          }
                        ]
                      }
                    }
                  ]
                }
                """;

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(fakeGeminiBody);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        ModelInferenceResult mlResult = new ModelInferenceResult(1, 0.40f, 0.60f, true, null);
        GeminiAnalysisDto result = geminiService.analyzeUrl("https://chatgpt.com", mlResult, Collections.emptyList());

        assertEquals("SUCCESS", result.getStatus());
        assertEquals("NOT_OBVIOUSLY_SUSPICIOUS", result.getAssessment());
        assertEquals(2, result.getIndicators().size());
        assertTrue(result.getExplanation().contains("No deceptive indicators"));
        assertEquals("gemini-3.8-flash", result.getProviderModel());
        // Verify key never leaks into result
        assertFalse(result.getExplanation().contains("valid-secret-key"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testMalformedResponseGracefullyHandled() throws Exception {
        geminiService.setEnabled(true);
        geminiService.setApiKey("valid-secret-key");

        String malformedBody = "{ \"candidates\": [ { \"content\": { \"parts\": [ { \"text\": \"NOT VALID JSON\" } ] } } ] }";

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(malformedBody);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        GeminiAnalysisDto result = geminiService.analyzeUrl("https://example.com", null, Collections.emptyList());

        assertEquals("UNAVAILABLE", result.getStatus());
        assertTrue(result.getExplanation().contains("Failed to parse"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testQuotaErrorHandledGracefully() throws Exception {
        geminiService.setEnabled(true);
        geminiService.setApiKey("valid-secret-key");

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(429);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        GeminiAnalysisDto result = geminiService.analyzeUrl("https://example.com", null, Collections.emptyList());

        assertEquals("UNAVAILABLE", result.getStatus());
        assertTrue(result.getExplanation().contains("quota") || result.getExplanation().contains("rate limit"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testModelNotFoundHttp404HandledGracefully() throws Exception {
        geminiService.setEnabled(true);
        geminiService.setApiKey("valid-secret-key");
        geminiService.setModel("non-existent-model");

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(404);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        GeminiAnalysisDto result = geminiService.analyzeUrl("https://example.com", null, Collections.emptyList());

        assertEquals("UNAVAILABLE", result.getStatus());
        assertTrue(result.getExplanation().contains("not found"));
        assertTrue(result.getExplanation().contains("404"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testAuthenticationErrorHttp401HandledGracefully() throws Exception {
        geminiService.setEnabled(true);
        geminiService.setApiKey("invalid-key");

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(401);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        GeminiAnalysisDto result = geminiService.analyzeUrl("https://example.com", null, Collections.emptyList());

        assertEquals("UNAVAILABLE", result.getStatus());
        assertTrue(result.getExplanation().contains("authentication failed"));
        assertFalse(result.getExplanation().contains("invalid-key"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testBadRequestHttp400HandledGracefully() throws Exception {
        geminiService.setEnabled(true);
        geminiService.setApiKey("valid-secret-key");

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(400);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        GeminiAnalysisDto result = geminiService.analyzeUrl("https://example.com", null, Collections.emptyList());

        assertEquals("UNAVAILABLE", result.getStatus());
        assertTrue(result.getExplanation().contains("400"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testTimeoutHandledGracefully() throws Exception {
        geminiService.setEnabled(true);
        geminiService.setApiKey("valid-secret-key");

        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new HttpTimeoutException("Connection timed out"));

        GeminiAnalysisDto result = geminiService.analyzeUrl("https://example.com", null, Collections.emptyList());

        assertEquals("UNAVAILABLE", result.getStatus());
        assertTrue(result.getExplanation().contains("timed out"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testInvalidEnumFallsBackToInsufficientEvidence() throws Exception {
        geminiService.setEnabled(true);
        geminiService.setApiKey("valid-secret-key");

        String invalidEnumBody = """
                {
                  "candidates": [
                    {
                      "content": {
                        "parts": [
                          {
                            "text": "{\\"assessment\\": \\"COMPLETELY_SAFE\\", \\"indicators\\": [], \\"explanation\\": \\"Unknown enum value returned.\\", \\"limitations\\": []}"
                          }
                        ]
                      }
                    }
                  ]
                }
                """;

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.body()).thenReturn(invalidEnumBody);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResponse);

        GeminiAnalysisDto result = geminiService.analyzeUrl("https://example.com", null, Collections.emptyList());

        assertEquals("SUCCESS", result.getStatus());
        assertEquals("INSUFFICIENT_EVIDENCE", result.getAssessment());
    }
}
