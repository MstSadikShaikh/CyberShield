package com.cybershield.detector.service;

import com.cybershield.detector.dto.*;
import com.cybershield.detector.entity.ScanRecord;
import com.cybershield.detector.exception.ResourceNotFoundException;
import com.cybershield.detector.repository.ScanRecordRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class ScanService {

    private static final Logger log = LoggerFactory.getLogger(ScanService.class);

    private final UrlValidatorService urlValidatorService;
    private final UrlFeatureExtractor urlFeatureExtractor;
    private final ModelInferenceService modelInferenceService;
    private final RiskAssessmentService riskAssessmentService;
    private final ThreatIntelligenceService threatIntelligenceService;
    private final GeminiAnalysisService geminiAnalysisService;
    private final ScanRecordRepository scanRecordRepository;
    private final ObjectMapper objectMapper;

    @Value("${cybershield.history.max-limit:100}")
    private int maxHistoryLimit;

    @Value("${cybershield.gemini.always-run:false}")
    private boolean geminiAlwaysRun;

    public ScanService(UrlValidatorService urlValidatorService,
                       UrlFeatureExtractor urlFeatureExtractor,
                       ModelInferenceService modelInferenceService,
                       RiskAssessmentService riskAssessmentService,
                       ThreatIntelligenceService threatIntelligenceService,
                       GeminiAnalysisService geminiAnalysisService,
                       ScanRecordRepository scanRecordRepository,
                       ObjectMapper objectMapper) {
        this.urlValidatorService = urlValidatorService;
        this.urlFeatureExtractor = urlFeatureExtractor;
        this.modelInferenceService = modelInferenceService;
        this.riskAssessmentService = riskAssessmentService;
        this.threatIntelligenceService = threatIntelligenceService;
        this.geminiAnalysisService = geminiAnalysisService;
        this.scanRecordRepository = scanRecordRepository;
        this.objectMapper = objectMapper;
    }

    /**
     * Executes end-to-end URL scanning: validation, feature extraction, ML inference,
     * threat intelligence check, secondary AI analysis (if indicated), hybrid calibration,
     * persistence, and response building.
     */
    public ScanResponseDto scanUrl(String rawUrl) {
        // 1. Strict URL validation and safe normalization
        String normalizedUrl = urlValidatorService.validateAndNormalize(rawUrl);

        // 2. Extract cybersecurity heuristic indicators
        List<UrlIndicatorDto> indicators = urlFeatureExtractor.extractIndicators(normalizedUrl);

        // 3. Pretrained ML model inference (Java ONNX Runtime)
        ModelInferenceResult mlResult = modelInferenceService.predict(normalizedUrl);

        // 4. Query Threat Intelligence service (Google Web Risk or replaceable feed)
        ThreatIntelligenceDto threatIntel = threatIntelligenceService.checkUrl(normalizedUrl);

        // 5. Evaluate whether Gemini secondary analysis is required
        GeminiAnalysisDto geminiAnalysis = determineAndExecuteGeminiAnalysis(normalizedUrl, mlResult, indicators, threatIntel);

        // 6. Calibrate hybrid assessment combining ML, Threat Intel, and Gemini
        RiskAssessmentService.AssessmentResult assessment = riskAssessmentService.assessRisk(
                mlResult, indicators, threatIntel, geminiAnalysis
        );

        // 7. Sanitize URL tokens before database storage
        String sanitizedUrl = urlValidatorService.sanitizeForStorage(normalizedUrl);

        // Serialize indicators, precautions, threat matches, and gemini assessment to JSON for persistence
        String indicatorsJson = "[]";
        String precautionsJson = "[]";
        String threatCategoriesJson = "[]";
        String geminiAssessmentJson = null;

        try {
            indicatorsJson = objectMapper.writeValueAsString(indicators);
            precautionsJson = objectMapper.writeValueAsString(assessment.precautions());
            if (threatIntel != null && !threatIntel.getThreatMatches().isEmpty()) {
                threatCategoriesJson = objectMapper.writeValueAsString(threatIntel.getThreatMatches());
            }
            if (geminiAnalysis != null && "SUCCESS".equalsIgnoreCase(geminiAnalysis.getStatus())) {
                geminiAssessmentJson = objectMapper.writeValueAsString(geminiAnalysis);
            }
        } catch (Exception e) {
            log.warn("Failed to serialize scan metadata to JSON: {}", e.getMessage());
        }

        // 8. Persist to MySQL database with graceful resilience if DB is offline
        ScanRecord record = new ScanRecord(
                normalizedUrl,
                sanitizedUrl,
                assessment.prediction(),
                assessment.riskScore(),
                assessment.riskLevel(),
                modelInferenceService.getModelVersion(),
                mlResult != null ? (double) mlResult.probPhishing() : 0.0,
                assessment.explanation(),
                indicatorsJson,
                precautionsJson
        );

        // Store hybrid detection fields
        if (threatIntel != null) {
            record.setThreatIntelStatus(threatIntel.getStatus());
            record.setThreatIntelSource(threatIntel.getSource());
            record.setThreatCategoriesJson(threatCategoriesJson);
        }
        if (geminiAnalysis != null) {
            record.setGeminiStatus(geminiAnalysis.getStatus());
            record.setGeminiModel(geminiAnalysis.getProviderModel());
            record.setGeminiAssessmentJson(geminiAssessmentJson);
        }
        record.setFinalAssessment(assessment.finalAssessment());

        Long savedId = null;
        Instant scannedTime = Instant.now();
        try {
            ScanRecord saved = scanRecordRepository.save(record);
            savedId = saved.getId();
            scannedTime = saved.getScannedAt();
        } catch (Exception e) {
            log.warn("Database persistence failed (MySQL may be offline or uninitialized): {}. Scan completed in-memory.", e.getMessage());
        }

        // 9. Assemble response DTO
        ScanResponseDto response = new ScanResponseDto();
        response.setId(savedId);
        response.setSubmittedUrl(normalizedUrl);
        response.setSanitizedUrl(sanitizedUrl);
        response.setPrediction(assessment.prediction());
        response.setRiskScore(assessment.riskScore());
        response.setRiskLevel(assessment.riskLevel());
        response.setModelVersion(modelInferenceService.getModelVersion());

        if (mlResult != null) {
            response.setModelProbability((double) mlResult.probPhishing());
            String mlLabel = mlResult.predictedClass() == 1 ? "PHISHING" : "LEGITIMATE";
            double pct = Math.round(mlResult.probPhishing() * 1000.0) / 10.0;
            response.setModelAssessment(mlLabel + " (" + pct + "% model likelihood)");
        } else {
            response.setModelAssessment("UNAVAILABLE");
        }

        response.setFinalAssessment(assessment.finalAssessment());
        response.setExplanation(assessment.explanation());
        response.setPrecautions(assessment.precautions());
        response.setIndicators(indicators);
        response.setLimitations(assessment.limitations());
        response.setThreatIntelligence(threatIntel);
        response.setGeminiAnalysis(geminiAnalysis);
        response.setScannedAt(scannedTime);

        return response;
    }

    /**
     * Determines whether Gemini secondary analysis should be invoked to conserve API quotas
     * while adjudicating uncertain ML predictions, borderline ranges, or heuristic disagreements.
     */
    private GeminiAnalysisDto determineAndExecuteGeminiAnalysis(String url,
                                                               ModelInferenceResult mlResult,
                                                               List<UrlIndicatorDto> indicators,
                                                               ThreatIntelligenceDto threatIntel) {
        if (!geminiAnalysisService.isConfigured()) {
            return GeminiAnalysisDto.notConfigured(geminiAnalysisService.getModel());
        }

        // Skip if threat intelligence already confirmed an active threat match
        if (threatIntel != null && "MATCH_FOUND".equalsIgnoreCase(threatIntel.getStatus())) {
            return GeminiAnalysisDto.skipped(geminiAnalysisService.getModel(),
                    "Threat feed confirmed malicious signature; secondary AI check skipped.");
        }

        if (mlResult == null) {
            // ML failed; invoke Gemini for secondary qualitative assessment
            return geminiAnalysisService.analyzeUrl(url, null, indicators);
        }

        float probPhishing = mlResult.probPhishing();
        long predictedClass = mlResult.predictedClass();

        // Check if there are any danger/warning heuristic signals
        boolean hasThreatHeuristics = indicators != null && indicators.stream()
                .anyMatch(i -> "DANGER".equals(i.getSeverity()) || "WARNING".equals(i.getSeverity()));

        // Case 1: Always run if configured by property
        if (geminiAlwaysRun) {
            return geminiAnalysisService.analyzeUrl(url, mlResult, indicators);
        }

        // Case 2: Evidence conflict (e.g. chatgpt.com scenario: predictedClass == 1 but zero threat heuristics)
        if (predictedClass == 1 && !hasThreatHeuristics) {
            log.info("Invoking Gemini secondary analysis: ML predicted phishing but structural heuristics are clean (conflict resolution).");
            return geminiAnalysisService.analyzeUrl(url, mlResult, indicators);
        }

        // Case 3: Uncertain ML probability zone (0.40 <= prob <= 0.65)
        if (probPhishing >= 0.40f && probPhishing <= 0.65f) {
            log.info("Invoking Gemini secondary analysis: ML probability in uncertain range ({}%).", Math.round(probPhishing * 100));
            return geminiAnalysisService.analyzeUrl(url, mlResult, indicators);
        }

        // Conclusive ML result with aligning heuristics: skip to conserve quota
        return GeminiAnalysisDto.skipped(geminiAnalysisService.getModel(),
                "ML model output and structural indicators are decisive; secondary AI check skipped to conserve quota.");
    }

    /**
     * Retrieves recent scan history from MySQL.
     */
    @Transactional(readOnly = true)
    public List<ScanSummaryDto> getRecentScans(int limit) {
        int boundedLimit = Math.min(Math.max(1, limit), maxHistoryLimit);
        try {
            return scanRecordRepository.findAllByOrderByScannedAtDesc(PageRequest.of(0, boundedLimit))
                    .stream()
                    .map(r -> new ScanSummaryDto(
                            r.getId(),
                            r.getSanitizedUrl(),
                            r.getPrediction(),
                            r.getRiskScore(),
                            r.getRiskLevel(),
                            r.getScannedAt()
                    ))
                    .collect(Collectors.toList());
        } catch (Exception e) {
            log.warn("Unable to fetch scan history from MySQL: {}", e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Retrieves a single full scan result by ID.
     */
    @Transactional(readOnly = true)
    public ScanResponseDto getScanById(Long id) {
        ScanRecord record;
        try {
            record = scanRecordRepository.findById(id)
                    .orElseThrow(() -> new ResourceNotFoundException("Scan record with ID " + id + " not found."));
        } catch (ResourceNotFoundException e) {
            throw e;
        } catch (Exception e) {
            log.error("Database query failed for ID {}: {}", id, e.getMessage());
            throw new ResourceNotFoundException("Scan record with ID " + id + " is not accessible.");
        }

        List<UrlIndicatorDto> indicators = new ArrayList<>();
        List<String> precautions = new ArrayList<>();
        List<String> threatMatches = new ArrayList<>();
        GeminiAnalysisDto geminiAnalysis = null;

        try {
            if (record.getIndicatorsJson() != null) {
                indicators = objectMapper.readValue(record.getIndicatorsJson(), new TypeReference<>() {});
            }
            if (record.getPrecautionsJson() != null) {
                precautions = objectMapper.readValue(record.getPrecautionsJson(), new TypeReference<>() {});
            }
            if (record.getThreatCategoriesJson() != null && !record.getThreatCategoriesJson().isBlank()) {
                threatMatches = objectMapper.readValue(record.getThreatCategoriesJson(), new TypeReference<>() {});
            }
            if (record.getGeminiAssessmentJson() != null && !record.getGeminiAssessmentJson().isBlank()) {
                geminiAnalysis = objectMapper.readValue(record.getGeminiAssessmentJson(), GeminiAnalysisDto.class);
            }
        } catch (Exception e) {
            log.warn("Failed to deserialize JSON metadata for record {}: {}", id, e.getMessage());
        }

        ThreatIntelligenceDto threatIntel = new ThreatIntelligenceDto(
                record.getThreatIntelStatus() != null ? record.getThreatIntelStatus() : "NOT_CONFIGURED",
                record.getThreatIntelSource() != null ? record.getThreatIntelSource() : "Threat Intelligence Feed",
                threatMatches,
                null
        );

        if (geminiAnalysis == null) {
            geminiAnalysis = new GeminiAnalysisDto(
                    record.getGeminiStatus() != null ? record.getGeminiStatus() : "NOT_CONFIGURED",
                    "NOT_PERFORMED",
                    new ArrayList<>(),
                    "Gemini secondary assessment was not performed or not configured for this historical record.",
                    List.of("Historical scan prior to Gemini integration or check was skipped."),
                    record.getGeminiModel() != null ? record.getGeminiModel() : "gemini-3.8-flash"
            );
        }

        ScanResponseDto response = new ScanResponseDto();
        response.setId(record.getId());
        response.setSubmittedUrl(record.getSubmittedUrl());
        response.setSanitizedUrl(record.getSanitizedUrl());
        response.setPrediction(record.getPrediction());
        response.setRiskScore(record.getRiskScore());
        response.setRiskLevel(record.getRiskLevel());
        response.setModelVersion(record.getModelVersion());
        response.setModelProbability(record.getModelProbability());

        if (record.getModelProbability() != null) {
            double pct = Math.round(record.getModelProbability() * 1000.0) / 10.0;
            response.setModelAssessment(record.getPrediction() + " (" + pct + "% model likelihood)");
        }

        response.setFinalAssessment(record.getFinalAssessment() != null ? record.getFinalAssessment() : record.getPrediction());
        response.setExplanation(record.getExplanation());
        response.setPrecautions(precautions);
        response.setIndicators(indicators);
        response.setThreatIntelligence(threatIntel);
        response.setGeminiAnalysis(geminiAnalysis);
        response.setScannedAt(record.getScannedAt());

        return response;
    }
}
