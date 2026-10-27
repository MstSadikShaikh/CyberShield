package com.cybershield.detector.service;

import com.cybershield.detector.dto.GeminiAnalysisDto;
import com.cybershield.detector.dto.ThreatIntelligenceDto;
import com.cybershield.detector.dto.UrlIndicatorDto;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class RiskAssessmentService {

    public record AssessmentResult(
            String prediction,     // "PHISHING", "LEGITIMATE", "UNCERTAIN"
            double riskScore,      // 0.0 to 100.0
            String riskLevel,      // "LOW", "MEDIUM", "HIGH", "CRITICAL"
            String finalAssessment,// "CONFIRMED_THREAT", "HIGH_RISK_ML", "CONFLICT_EVIDENCE_UNCERTAIN", "CONFLICT_ELEVATED", "CONFLICT_UNRESOLVED", "UNCERTAIN_MODEL", "LOW_RISK_LEGITIMATE", "MODEL_UNAVAILABLE"
            String explanation,
            List<String> precautions,
            List<String> limitations
    ) {}

    /**
     * Backward-compatible overload for local assessments without external providers.
     */
    public AssessmentResult assessRisk(ModelInferenceResult mlResult, List<UrlIndicatorDto> indicators) {
        return assessRisk(mlResult, indicators, null, null);
    }

    /**
     * Combines genuine ONNX model inference outputs, structural cybersecurity indicators,
     * external Threat Intelligence, and secondary Gemini AI analysis into a transparent, non-averaged decision.
     */
    public AssessmentResult assessRisk(ModelInferenceResult mlResult,
                                       List<UrlIndicatorDto> indicators,
                                       ThreatIntelligenceDto threatIntel,
                                       GeminiAnalysisDto geminiAnalysis) {

        List<String> systemLimitations = new ArrayList<>();
        systemLimitations.add("Analysis is based on passive lexical, structural, and threat-feed indicators without active network crawling.");
        systemLimitations.add("Model outputs represent uncalibrated LinearSVM distance scores, not guaranteed real-world probabilities.");

        // Rule A: Confirmed threat match from Threat Intelligence feed
        if (threatIntel != null && "MATCH_FOUND".equalsIgnoreCase(threatIntel.getStatus())) {
            List<String> threats = threatIntel.getThreatMatches();
            double score = 98.0;
            String riskLevel = "CRITICAL";
            String prediction = "PHISHING";
            String finalAssessment = "CONFIRMED_THREAT";

            String explanation = "Confirmed threat match detected by " + threatIntel.getSource() +
                    " (threat categories: " + (threats.isEmpty() ? "MALICIOUS" : String.join(", ", threats)) +
                    "). Immediate defensive containment required.";

            List<String> precautions = generatePrecautions(riskLevel);
            precautions.add(0, "CRITICAL: Do not visit this site; threat intelligence feed independently flagged active malicious operations.");

            return new AssessmentResult(prediction, score, riskLevel, finalAssessment, explanation, precautions, systemLimitations);
        }

        // Rule G: ML Model Unavailable
        if (mlResult == null) {
            String finalAssessment = "MODEL_UNAVAILABLE";
            String prediction = "UNCERTAIN";
            double score = 50.0;
            String riskLevel = "MEDIUM";
            String explanation = "Local ONNX machine learning model was unavailable for inference. Classified conservatively as UNCERTAIN.";
            systemLimitations.add("Pretrained machine-learning model failed to execute; assessment is incomplete.");
            return new AssessmentResult(prediction, score, riskLevel, finalAssessment, explanation, generatePrecautions(riskLevel), systemLimitations);
        }

        // 1. Calculate base score from ML model score (0.0 to 100.0)
        float probPhishing = mlResult.probPhishing();
        long predictedClass = mlResult.predictedClass();
        double score = probPhishing * 100.0;

        // 2. Count threat indicators and calibrate based on heuristics
        boolean hasIpHost = false;
        boolean hasAtSymbol = false;
        int dangerCount = 0;
        int warningCount = 0;
        List<String> warningDescriptions = new ArrayList<>();

        if (indicators != null) {
            for (UrlIndicatorDto indicator : indicators) {
                if ("DANGER".equals(indicator.getSeverity())) {
                    dangerCount++;
                    if ("Host Type".equals(indicator.getName())) hasIpHost = true;
                    if ("URL Obfuscation".equals(indicator.getName())) hasAtSymbol = true;
                    warningDescriptions.add(indicator.getName() + " (" + indicator.getValue() + ")");
                } else if ("WARNING".equals(indicator.getSeverity())) {
                    warningCount++;
                    warningDescriptions.add(indicator.getName() + " (" + indicator.getValue() + ")");
                }
            }
        }

        if (hasIpHost) {
            score = Math.max(score, 65.0); // Raw IP host is inherently suspicious
        }
        if (hasAtSymbol) {
            score = Math.max(score, 80.0); // Embedded @ credential spoofing
        }

        score = Math.min(100.0, Math.max(0.0, score));
        double finalScore = Math.round(score * 10.0) / 10.0;

        // Disclose threat intel status in limitations
        if (threatIntel == null || "NOT_CONFIGURED".equals(threatIntel.getStatus())) {
            systemLimitations.add("Threat intelligence provider is not configured; scan relied on local ML and heuristics.");
        } else if ("UNAVAILABLE".equals(threatIntel.getStatus())) {
            systemLimitations.add("Threat intelligence check was unavailable: " + threatIntel.getDetails());
        } else if ("NO_MATCH".equals(threatIntel.getStatus())) {
            systemLimitations.add("Threat intelligence found no known signatures (negative lookup does not prove safety).");
        }

        // Disclose Gemini secondary analysis status in limitations
        if (geminiAnalysis != null && "SUCCESS".equalsIgnoreCase(geminiAnalysis.getStatus())) {
            systemLimitations.add("Gemini secondary analysis provides qualitative lexical opinion only; it cannot prove a URL is legitimate or safe.");
        }

        // Rule C: Conflicting Evidence (e.g., chatgpt.com scenario)
        // ML predicted phishing (predictedClass == 1 or prob >= 0.50), but score < 75.0 and ZERO danger/warning indicators,
        // and Threat Intel shows no active match.
        boolean hasNoThreatHeuristics = (dangerCount == 0 && warningCount == 0);
        boolean isConflictCandidate = (predictedClass == 1 || finalScore >= 50.0) && finalScore < 75.0 && hasNoThreatHeuristics;

        if (isConflictCandidate) {
            if (geminiAnalysis != null && "SUCCESS".equalsIgnoreCase(geminiAnalysis.getStatus())) {
                if ("NOT_OBVIOUSLY_SUSPICIOUS".equalsIgnoreCase(geminiAnalysis.getAssessment())) {
                    // Detection Safety: Gemini's qualitative opinion alone cannot prove legitimacy over a conflicting ML detection
                    String finalAssessment = "CONFLICT_EVIDENCE_UNCERTAIN";
                    String prediction = "UNCERTAIN";
                    double calibratedScore = 45.0;
                    String riskLevel = "MEDIUM";
                    String explanation = "The ML model flagged phishing likelihood (uncalibrated score: " +
                            Math.round(probPhishing * 100) + "%), but zero heuristic threat indicators were detected and " +
                            "Gemini secondary AI observed no obvious deceptive syntax in the domain name. Because qualitative AI analysis alone cannot certify legitimacy over an ML signal, this link is classified defensively as UNCERTAIN. Disagreement documented.";
                    return new AssessmentResult(prediction, calibratedScore, riskLevel, finalAssessment, explanation, generatePrecautions(riskLevel), systemLimitations);

                } else if ("SUSPICIOUS".equalsIgnoreCase(geminiAnalysis.getAssessment())) {
                    String finalAssessment = "CONFLICT_ELEVATED";
                    String prediction = "PHISHING";
                    double calibratedScore = Math.max(finalScore, 70.0);
                    String riskLevel = "HIGH";
                    String explanation = "Machine learning and Gemini secondary analysis both identified suspicious lexical patterns, despite standard structural heuristics.";
                    return new AssessmentResult(prediction, calibratedScore, riskLevel, finalAssessment, explanation, generatePrecautions(riskLevel), systemLimitations);

                } else {
                    String finalAssessment = "CONFLICT_UNRESOLVED";
                    String prediction = "UNCERTAIN";
                    double calibratedScore = 50.0;
                    String riskLevel = "MEDIUM";
                    String explanation = "Model prediction conflicted with clean structural heuristics, and secondary AI analysis reported insufficient evidence. Classified conservatively as UNCERTAIN.";
                    return new AssessmentResult(prediction, calibratedScore, riskLevel, finalAssessment, explanation, generatePrecautions(riskLevel), systemLimitations);
                }
            } else {
                // Gemini is unconfigured or unavailable during conflict
                String finalAssessment = "CONFLICT_UNRESOLVED";
                String prediction = "UNCERTAIN";
                double calibratedScore = 50.0;
                String riskLevel = "MEDIUM";
                String explanation = "The ML model predicted phishing likelihood (uncalibrated score: " + Math.round(probPhishing * 100) +
                        "%), but zero structural or lexical threat indicators were detected. Secondary AI analysis was not configured to adjudicate. Classified conservatively as UNCERTAIN.";
                systemLimitations.add("Secondary AI provider is unconfigured; conflicting ML and heuristic signals could not be independently arbitrated.");
                return new AssessmentResult(prediction, calibratedScore, riskLevel, finalAssessment, explanation, generatePrecautions(riskLevel), systemLimitations);
            }
        }

        // Rule B: High-Risk ML (with supporting heuristic indicators or score >= 75.0)
        // A Gemini benign assessment must not automatically override a strong ML phishing signal
        if (finalScore >= 75.0 || (predictedClass == 1 && finalScore >= 60.0 && (dangerCount > 0 || warningCount > 0))) {
            String prediction = "PHISHING";
            String riskLevel = finalScore >= 90.0 ? "CRITICAL" : "HIGH";
            String finalAssessment = "HIGH_RISK_ML";
            String explanation = generateExplanation(prediction, riskLevel, finalScore, probPhishing, warningDescriptions);
            return new AssessmentResult(prediction, finalScore, riskLevel, finalAssessment, explanation, generatePrecautions(riskLevel), systemLimitations);
        }

        // Rule D: Uncertain Model Range (40.0 <= finalScore < 65.0)
        if (finalScore >= 40.0) {
            if (geminiAnalysis != null && "SUCCESS".equalsIgnoreCase(geminiAnalysis.getStatus())) {
                if ("SUSPICIOUS".equalsIgnoreCase(geminiAnalysis.getAssessment())) {
                    String prediction = "PHISHING";
                    double elevatedScore = Math.max(finalScore, 72.0);
                    String riskLevel = "HIGH";
                    String finalAssessment = "AI_ELEVATED";
                    String explanation = "Borderline ML prediction (uncalibrated score: " + Math.round(probPhishing * 100) +
                            "%) was elevated to HIGH risk by Gemini secondary analysis: " + geminiAnalysis.getExplanation();
                    return new AssessmentResult(prediction, elevatedScore, riskLevel, finalAssessment, explanation, generatePrecautions(riskLevel), systemLimitations);
                } else if ("NOT_OBVIOUSLY_SUSPICIOUS".equalsIgnoreCase(geminiAnalysis.getAssessment())) {
                    // Reassurance noted, but qualitative opinion alone does not prove legitimacy
                    String prediction = "UNCERTAIN";
                    double calibratedScore = 40.0;
                    String riskLevel = "MEDIUM";
                    String finalAssessment = "UNCERTAIN_MODEL";
                    String explanation = "Uncertain ML prediction (uncalibrated score: " + Math.round(probPhishing * 100) +
                            "%). Gemini secondary review noted standard domain structure, but qualitative opinion alone cannot certify safety; retained as UNCERTAIN.";
                    return new AssessmentResult(prediction, calibratedScore, riskLevel, finalAssessment, explanation, generatePrecautions(riskLevel), systemLimitations);
                }
            }

            String prediction = "UNCERTAIN";
            String riskLevel = "MEDIUM";
            String finalAssessment = "UNCERTAIN_MODEL";
            String explanation = generateExplanation(prediction, riskLevel, finalScore, probPhishing, warningDescriptions);
            return new AssessmentResult(prediction, finalScore, riskLevel, finalAssessment, explanation, generatePrecautions(riskLevel), systemLimitations);
        }

        // Rule E: Low-Risk Legitimate (both ML and heuristics agree on low risk)
        String prediction = "LEGITIMATE";
        String riskLevel = "LOW";
        String finalAssessment = "LOW_RISK_LEGITIMATE";
        String explanation = generateExplanation(prediction, riskLevel, finalScore, probPhishing, warningDescriptions);
        return new AssessmentResult(prediction, finalScore, riskLevel, finalAssessment, explanation, generatePrecautions(riskLevel), systemLimitations);
    }

    private String generateExplanation(String prediction, String riskLevel, double score, float probPhishing, List<String> warnings) {
        int pct = (int) Math.round(probPhishing * 100.0);

        if ("PHISHING".equals(prediction)) {
            StringBuilder sb = new StringBuilder();
            sb.append("The pre-trained machine-learning model classified this URL with an uncalibrated model-reported likelihood of ").append(pct)
              .append("%. Overall risk score evaluated to ")
              .append(score).append("/100 (").append(riskLevel).append(").");

            if (!warnings.isEmpty()) {
                sb.append(" Additional threat signals observed: ").append(String.join("; ", warnings)).append(".");
            }
            sb.append(" This link demonstrates structural and lexical characteristics commonly observed in credential theft and deception campaigns.");
            return sb.toString();

        } else if ("UNCERTAIN".equals(prediction)) {
            StringBuilder sb = new StringBuilder();
            sb.append("Analysis yielded an ambiguous assessment (risk score: ")
              .append(score).append("/100, uncalibrated ML score: ").append(pct).append("%).");

            if (!warnings.isEmpty()) {
                sb.append(" Several elevated indicators were detected, including ").append(String.join(", ", warnings)).append(".");
            }
            sb.append(" Exercise heightened vigilance before interacting with or submitting any data on this destination.");
            return sb.toString();

        } else {
            return "The pre-trained classification model and heuristic analyzer found no dominant phishing signals " +
                   "(uncalibrated ML score: " + pct + "%, risk score: " + score + "/100). " +
                   "Structural features align with standard legitimate websites. Note: A low risk score does not guarantee " +
                   "absolute safety; always verify that the address bar matches the intended institution.";
        }
    }

    private List<String> generatePrecautions(String riskLevel) {
        List<String> precautions = new ArrayList<>();

        if ("CRITICAL".equals(riskLevel) || "HIGH".equals(riskLevel)) {
            precautions.add("Do not visit this URL, submit passwords, or provide payment details.");
            precautions.add("If you already accessed this link, immediately change affected passwords and revoke active sessions.");
            precautions.add("Enable Multi-Factor Authentication (MFA) with an authenticator app or hardware security key.");
            precautions.add("Report the URL to your institution's security operations center (SOC) or the Anti-Phishing Working Group (APWG).");
            precautions.add("Never download or execute files delivered by unverified links.");
        } else if ("MEDIUM".equals(riskLevel)) {
            precautions.add("Verify the domain name character-by-character to prevent typosquatting and lookalike attacks.");
            precautions.add("Navigate to the service directly via a bookmark or search engine rather than clicking unsolicited links.");
            precautions.add("Do not accept browser notifications or certificate bypass prompts from this domain.");
            precautions.add("Confirm that Multi-Factor Authentication is active on any account associated with this service.");
        } else {
            precautions.add("Verify that the domain matches the authentic organization you intended to visit.");
            precautions.add("Confirm that the browser displays a valid HTTPS padlock and valid SSL certificate.");
            precautions.add("Always maintain caution when following links received in emails, text messages, or direct messages.");
        }

        return precautions;
    }
}
