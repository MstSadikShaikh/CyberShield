package com.cybershield.detector.service;

public record ModelInferenceResult(
        long predictedClass,       // 0 = Legitimate, 1 = Phishing
        float probLegitimate,      // Model probability for class 0
        float probPhishing,        // Model probability for class 1
        boolean success,
        String errorMessage
) {
    public static ModelInferenceResult error(String message) {
        return new ModelInferenceResult(-1, 0.0f, 0.0f, false, message);
    }
}
