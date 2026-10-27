package com.cybershield.detector;

import com.cybershield.detector.dto.GeminiAnalysisDto;
import com.cybershield.detector.dto.ThreatIntelligenceDto;
import com.cybershield.detector.dto.UrlIndicatorDto;
import com.cybershield.detector.service.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class RegressionUrlsTest {

    private static final Logger log = LoggerFactory.getLogger(RegressionUrlsTest.class);

    private OnnxModelInferenceService onnxService;
    private UrlFeatureExtractor featureExtractor;
    private RiskAssessmentService assessmentService;
    private UrlValidatorService validatorService;

    @BeforeEach
    public void setUp() {
        validatorService = new UrlValidatorService();
        onnxService = new OnnxModelInferenceService(new org.springframework.core.io.DefaultResourceLoader());
        onnxService.initialize();
        featureExtractor = new UrlFeatureExtractor();
        assessmentService = new RiskAssessmentService();
    }

    @Test
    public void testRegressionChatGPTFalsePositiveAnalysis() {
        String url = "https://chatgpt.com/";
        String normalized = validatorService.validateAndNormalize(url);

        ModelInferenceResult mlResult = onnxService.predict(normalized);
        List<UrlIndicatorDto> indicators = featureExtractor.extractIndicators(normalized);

        log.info("REGRESSION [chatgpt.com]: predictedClass={}, probLegit={}, probPhish={}",
                mlResult.predictedClass(), mlResult.probLegitimate(), mlResult.probPhishing());

        // Baseline ONNX model classifies chatgpt.com as class 1 (phishing ~62%) due to short brand name lack in training set
        assertEquals(1, mlResult.predictedClass(), "Actual pretrained ONNX model predicts class 1 on chatgpt.com");
        assertTrue(mlResult.probPhishing() > 0.50f && mlResult.probPhishing() < 0.75f, "Probability is in borderline 50-75% zone");

        // Verify that structural heuristics have ZERO danger or warning signals
        long threatSignals = indicators.stream()
                .filter(i -> "DANGER".equals(i.getSeverity()) || "WARNING".equals(i.getSeverity()))
                .count();
        assertEquals(0, threatSignals, "Structural heuristics for chatgpt.com must have 0 threat signals");

        // When Gemini is simulated with NOT_OBVIOUSLY_SUSPICIOUS, the hybrid orchestrator handles the conflict defensively
        GeminiAnalysisDto gemini = new GeminiAnalysisDto(
                "SUCCESS",
                "NOT_OBVIOUSLY_SUSPICIOUS",
                List.of("Clean structure", "Standard domain"),
                "No deceptive brand impersonation observed.",
                List.of("Passive analysis only"),
                "gemini-3.8-flash"
        );
        ThreatIntelligenceDto threatIntel = ThreatIntelligenceDto.noMatch("Google Web Risk API");

        RiskAssessmentService.AssessmentResult hybridResult = assessmentService.assessRisk(
                mlResult, indicators, threatIntel, gemini
        );

        // Under detection safety, qualitative opinion alone cannot certify legitimacy over an ML phishing flag
        assertEquals("UNCERTAIN", hybridResult.prediction(), "Conflicting evidence must resolve to UNCERTAIN, not falsely claim LEGITIMATE");
        assertEquals("MEDIUM", hybridResult.riskLevel());
        assertEquals("CONFLICT_EVIDENCE_UNCERTAIN", hybridResult.finalAssessment());
        assertEquals(45.0, hybridResult.riskScore());
    }

    @Test
    public void testRegressionGoogleSearch() {
        String url = "https://www.google.com/";
        String normalized = validatorService.validateAndNormalize(url);

        ModelInferenceResult mlResult = onnxService.predict(normalized);
        List<UrlIndicatorDto> indicators = featureExtractor.extractIndicators(normalized);

        log.info("REGRESSION [google.com]: predictedClass={}, probLegit={}, probPhish={}",
                mlResult.predictedClass(), mlResult.probLegitimate(), mlResult.probPhishing());

        assertEquals(0, mlResult.predictedClass(), "ONNX model predicts class 0 (Legitimate)");
        assertTrue(mlResult.probPhishing() < 0.30f);

        RiskAssessmentService.AssessmentResult result = assessmentService.assessRisk(
                mlResult, indicators, ThreatIntelligenceDto.noMatch("Google Web Risk API"), null
        );

        assertEquals("LEGITIMATE", result.prediction());
        assertEquals("LOW", result.riskLevel());
    }

    @Test
    public void testRegressionWikipediaArticle() {
        String url = "https://en.wikipedia.org/wiki/Computer_security";
        String normalized = validatorService.validateAndNormalize(url);

        ModelInferenceResult mlResult = onnxService.predict(normalized);
        List<UrlIndicatorDto> indicators = featureExtractor.extractIndicators(normalized);

        log.info("REGRESSION [wikipedia]: predictedClass={}, probLegit={}, probPhish={}",
                mlResult.predictedClass(), mlResult.probLegitimate(), mlResult.probPhishing());

        assertEquals(0, mlResult.predictedClass(), "ONNX model predicts class 0 for Wikipedia");

        RiskAssessmentService.AssessmentResult result = assessmentService.assessRisk(
                mlResult, indicators, ThreatIntelligenceDto.noMatch("Google Web Risk API"), null
        );

        assertEquals("LEGITIMATE", result.prediction());
        assertEquals("LOW", result.riskLevel());
    }

    @Test
    public void testRegressionSyntheticPhishingUrl() {
        // Synthetic phishing URL testing - strictly never connected to
        String url = "http://paypal-security-verification-update.com.suspicious-login.ru/signin";
        String normalized = validatorService.validateAndNormalize(url);

        ModelInferenceResult mlResult = onnxService.predict(normalized);
        List<UrlIndicatorDto> indicators = featureExtractor.extractIndicators(normalized);

        log.info("REGRESSION [synthetic-phishing]: predictedClass={}, probLegit={}, probPhish={}",
                mlResult.predictedClass(), mlResult.probLegitimate(), mlResult.probPhishing());

        // Model predicts phishing
        assertEquals(1, mlResult.predictedClass(), "Model must detect high phishing probability on synthetic phishing link");
        assertTrue(mlResult.probPhishing() > 0.85f, "Probability must be high (> 85%)");

        // Structural indicators must contain warning signals (e.g. non-standard protocol HTTP, suspicious keywords)
        boolean hasWarningOrDanger = indicators.stream()
                .anyMatch(i -> "DANGER".equals(i.getSeverity()) || "WARNING".equals(i.getSeverity()));
        assertTrue(hasWarningOrDanger, "Structural indicators must flag heuristic warning signals");

        RiskAssessmentService.AssessmentResult result = assessmentService.assessRisk(
                mlResult, indicators, ThreatIntelligenceDto.noMatch("Google Web Risk API"), null
        );

        assertEquals("PHISHING", result.prediction());
        assertTrue(result.riskScore() >= 80.0);
    }
}
