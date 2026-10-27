package com.cybershield.detector;

import com.cybershield.detector.dto.GeminiAnalysisDto;
import com.cybershield.detector.dto.ThreatIntelligenceDto;
import com.cybershield.detector.dto.UrlIndicatorDto;
import com.cybershield.detector.service.ModelInferenceResult;
import com.cybershield.detector.service.RiskAssessmentService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class HybridAssessmentOrchestrationTest {

    private RiskAssessmentService assessmentService;

    @BeforeEach
    public void setUp() {
        assessmentService = new RiskAssessmentService();
    }

    @Test
    public void testConfirmedThreatMatchOverridesEverything() {
        // Even if ML probability was low (0.10)
        ModelInferenceResult mlResult = new ModelInferenceResult(0, 0.90f, 0.10f, true, null);
        ThreatIntelligenceDto threatIntel = ThreatIntelligenceDto.matchFound(
                "Google Web Risk API", List.of("SOCIAL_ENGINEERING", "MALWARE")
        );
        GeminiAnalysisDto gemini = GeminiAnalysisDto.skipped("gemini-3.8-flash", "Skipped");

        RiskAssessmentService.AssessmentResult result = assessmentService.assessRisk(
                mlResult, Collections.emptyList(), threatIntel, gemini
        );

        assertEquals("PHISHING", result.prediction());
        assertEquals("CRITICAL", result.riskLevel());
        assertEquals("CONFIRMED_THREAT", result.finalAssessment());
        assertTrue(result.riskScore() >= 95.0);
        assertTrue(result.explanation().contains("Google Web Risk API"));
        assertTrue(result.explanation().contains("SOCIAL_ENGINEERING"));
    }

    @Test
    public void testConflictResolutionWithGeminiBenignAssessmentReturnsUncertain() {
        // chatgpt.com scenario: ML model predicted phishing (prob 0.62) but zero threat heuristics
        ModelInferenceResult mlResult = new ModelInferenceResult(1, 0.38f, 0.62f, true, null);
        List<UrlIndicatorDto> cleanIndicators = List.of(
                new UrlIndicatorDto("Protocol", "https", "SAFE", "Standard HTTPS"),
                new UrlIndicatorDto("Entropy", "3.10", "INFO", "Typical lexical entropy")
        );
        ThreatIntelligenceDto threatIntel = ThreatIntelligenceDto.noMatch("Google Web Risk API");

        // Gemini secondary analysis assesses as NOT_OBVIOUSLY_SUSPICIOUS
        GeminiAnalysisDto gemini = new GeminiAnalysisDto(
                "SUCCESS",
                "NOT_OBVIOUSLY_SUSPICIOUS",
                List.of("Clean domain structure"),
                "No deceptive brand impersonation or malicious structural indicators observed.",
                List.of("Passive analysis only"),
                "gemini-3.8-flash"
        );

        RiskAssessmentService.AssessmentResult result = assessmentService.assessRisk(
                mlResult, cleanIndicators, threatIntel, gemini
        );

        // Detection Safety: Gemini qualitative opinion alone cannot prove a URL legitimate over an ML phishing detection
        assertEquals("UNCERTAIN", result.prediction(), "Conflicting ML and heuristics must resolve to UNCERTAIN, not falsely claim LEGITIMATE");
        assertEquals("MEDIUM", result.riskLevel());
        assertEquals("CONFLICT_EVIDENCE_UNCERTAIN", result.finalAssessment());
        assertEquals(45.0, result.riskScore());
        assertTrue(result.explanation().contains("qualitative AI analysis alone cannot certify legitimacy"));
    }

    @Test
    public void testConflictWithoutGeminiResolvesToUncertain() {
        // chatgpt.com scenario when Gemini is not configured
        ModelInferenceResult mlResult = new ModelInferenceResult(1, 0.38f, 0.62f, true, null);
        List<UrlIndicatorDto> cleanIndicators = List.of(
                new UrlIndicatorDto("Protocol", "https", "SAFE", "Standard HTTPS")
        );
        ThreatIntelligenceDto threatIntel = ThreatIntelligenceDto.notConfigured("Google Web Risk API");
        GeminiAnalysisDto gemini = GeminiAnalysisDto.notConfigured("gemini-3.8-flash");

        RiskAssessmentService.AssessmentResult result = assessmentService.assessRisk(
                mlResult, cleanIndicators, threatIntel, gemini
        );

        assertEquals("UNCERTAIN", result.prediction(), "Without secondary AI, conflicting ML and heuristics must be UNCERTAIN, not false positive");
        assertEquals("MEDIUM", result.riskLevel());
        assertEquals("CONFLICT_UNRESOLVED", result.finalAssessment());
        assertEquals(50.0, result.riskScore());
        assertTrue(result.explanation().contains("zero structural or lexical threat indicators were detected"));
    }

    @Test
    public void testUncertainMLRangeWithGeminiElevation() {
        // ML score 50% with uncertain probability
        ModelInferenceResult mlResult = new ModelInferenceResult(0, 0.50f, 0.50f, true, null);
        List<UrlIndicatorDto> indicators = List.of(
                new UrlIndicatorDto("Suspicious Words", "login, verify", "WARNING", "Contains credential prompts")
        );
        ThreatIntelligenceDto threatIntel = ThreatIntelligenceDto.noMatch("Google Web Risk API");
        GeminiAnalysisDto gemini = new GeminiAnalysisDto(
                "SUCCESS",
                "SUSPICIOUS",
                List.of("Suspicious lexical keywords mimic bank login"),
                "Observable indicators resemble credential harvesting pattern.",
                List.of("Passive analysis"),
                "gemini-3.8-flash"
        );

        RiskAssessmentService.AssessmentResult result = assessmentService.assessRisk(
                mlResult, indicators, threatIntel, gemini
        );

        assertEquals("PHISHING", result.prediction());
        assertEquals("HIGH", result.riskLevel());
        assertEquals("AI_ELEVATED", result.finalAssessment());
        assertTrue(result.riskScore() >= 70.0);
    }

    @Test
    public void testUncertainMLRangeWithGeminiBenignDoesNotProveLegitimacy() {
        // ML score 48% (uncertain) with clean heuristics
        ModelInferenceResult mlResult = new ModelInferenceResult(0, 0.52f, 0.48f, true, null);
        ThreatIntelligenceDto threatIntel = ThreatIntelligenceDto.noMatch("Google Web Risk API");
        GeminiAnalysisDto gemini = new GeminiAnalysisDto(
                "SUCCESS",
                "NOT_OBVIOUSLY_SUSPICIOUS",
                List.of("Clean structure"),
                "Standard domain structure.",
                List.of("Passive analysis"),
                "gemini-3.8-flash"
        );

        RiskAssessmentService.AssessmentResult result = assessmentService.assessRisk(
                mlResult, Collections.emptyList(), threatIntel, gemini
        );

        // Detection Safety: Gemini benign opinion alone must not prove an uncertain URL legitimate
        assertEquals("UNCERTAIN", result.prediction(), "Uncertain ML output must remain UNCERTAIN despite Gemini benign opinion");
        assertEquals("MEDIUM", result.riskLevel());
        assertEquals("UNCERTAIN_MODEL", result.finalAssessment());
        assertEquals(40.0, result.riskScore());
    }

    @Test
    public void testModelUnavailableGracefulHandling() {
        ThreatIntelligenceDto threatIntel = ThreatIntelligenceDto.noMatch("Google Web Risk API");
        GeminiAnalysisDto gemini = GeminiAnalysisDto.notConfigured("gemini-3.8-flash");

        RiskAssessmentService.AssessmentResult result = assessmentService.assessRisk(
                null, Collections.emptyList(), threatIntel, gemini
        );

        assertEquals("UNCERTAIN", result.prediction());
        assertEquals("MEDIUM", result.riskLevel());
        assertEquals("MODEL_UNAVAILABLE", result.finalAssessment());
        assertEquals(50.0, result.riskScore());
    }
}
