package com.cybershield.detector.service;

public interface ModelInferenceService {

    /**
     * Executes local ONNX model inference on the provided URL.
     */
    ModelInferenceResult predict(String url);

    /**
     * Checks if the model was loaded successfully during startup.
     */
    boolean isLoaded();

    /**
     * Returns the name of the model.
     */
    String getModelName();

    /**
     * Returns the version tag of the model.
     */
    String getModelVersion();

    /**
     * Returns the publisher's reported evaluation metric.
     */
    String getPublisherMetric();
}
