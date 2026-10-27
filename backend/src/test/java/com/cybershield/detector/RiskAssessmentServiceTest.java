package com.cybershield.detector;

import com.cybershield.detector.dto.UrlIndicatorDto;
import com.cybershield.detector.service.ModelInferenceResult;
import com.cybershield.detector.service.RiskAssessmentService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class RiskAssessmentServiceTest {

    private RiskAssessmentService assessmentService;

    @BeforeEach
    public void setUp() {
        assessmentService = new RiskAssessmentService();
    }

    @Test
    public void testHighProbabilityMapsToPhishing() {
        ModelInferenceResult mlResult = new ModelInferenceResult(1, 0.05f, 0.95f, true, null);
        RiskAssessmentService.AssessmentResult result = assessmentService.assessRisk(mlResult, Collections.emptyList());

        assertEquals("PHISHING", result.prediction());
        assertEquals("CRITICAL", result.riskLevel());
        assertTrue(result.riskScore() >= 90.0);
        assertFalse(result.precautions().isEmpty());
    }

    @Test
    public void testLowProbabilityMapsToLegitimate() {
        ModelInferenceResult mlResult = new ModelInferenceResult(0, 0.98f, 0.02f, true, null);
        RiskAssessmentService.AssessmentResult result = assessmentService.assessRisk(mlResult, Collections.emptyList());

        assertEquals("LEGITIMATE", result.prediction());
        assertEquals("LOW", result.riskLevel());
        assertTrue(result.riskScore() < 20.0);
        assertTrue(result.explanation().contains("no dominant phishing signals"));
    }

    @Test
    public void testModerateProbabilityMapsToUncertain() {
        ModelInferenceResult mlResult = new ModelInferenceResult(0, 0.52f, 0.48f, true, null);
        RiskAssessmentService.AssessmentResult result = assessmentService.assessRisk(mlResult, Collections.emptyList());

        assertEquals("UNCERTAIN", result.prediction());
        assertEquals("MEDIUM", result.riskLevel());
    }

    @Test
    public void testDangerIndicatorElevatesRisk() {
        ModelInferenceResult mlResult = new ModelInferenceResult(0, 0.80f, 0.20f, true, null);
        List<UrlIndicatorDto> indicators = List.of(
                new UrlIndicatorDto("Host Type", "192.168.1.1", "DANGER", "Raw IP address")
        );
        RiskAssessmentService.AssessmentResult result = assessmentService.assessRisk(mlResult, indicators);

        assertTrue(result.riskScore() >= 65.0, "Raw IP address must elevate risk score to at least 65.0");
    }
}
