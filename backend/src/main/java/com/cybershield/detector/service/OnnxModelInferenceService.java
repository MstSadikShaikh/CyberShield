package com.cybershield.detector.service;

import ai.onnxruntime.*;
import com.cybershield.detector.exception.ModelInferenceException;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.util.Collections;
import java.util.Map;

@Service
public class OnnxModelInferenceService implements ModelInferenceService {

    private static final Logger log = LoggerFactory.getLogger(OnnxModelInferenceService.class);

    private final ResourceLoader resourceLoader;

    @Value("${cybershield.model.path:classpath:model/model.onnx}")
    private String modelPath = "classpath:model/model.onnx";

    @Value("${cybershield.model.name:Pirocheto LinearSVM ONNX URL Classifier}")
    private String modelName = "Pirocheto LinearSVM ONNX URL Classifier";

    @Value("${cybershield.model.version:pirocheto-linear-svm-v1.0}")
    private String modelVersion = "pirocheto-linear-svm-v1.0";

    @Value("${cybershield.model.publisher-metric:94.86% Reported Accuracy (Sklearn LinearSVM)}")
    private String publisherMetric = "94.86% Reported Accuracy (Sklearn LinearSVM)";

    private OrtEnvironment env;
    private OrtSession session;
    private String inputName;
    private volatile boolean loaded = false;

    public OnnxModelInferenceService(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @PostConstruct
    public synchronized void initialize() {
        try {
            log.info("Initializing ONNX Model from path: {}", modelPath);
            Resource resource = resourceLoader.getResource(modelPath);

            if (!resource.exists()) {
                log.error("ONNX model artifact not found at: {}", modelPath);
                return;
            }

            byte[] modelBytes;
            try (InputStream is = resource.getInputStream()) {
                modelBytes = is.readAllBytes();
            }

            this.env = OrtEnvironment.getEnvironment("CyberShield-OrtEnv");
            OrtSession.SessionOptions options = new OrtSession.SessionOptions();
            options.setOptimizationLevel(OrtSession.SessionOptions.OptLevel.ALL_OPT);

            this.session = env.createSession(modelBytes, options);

            if (!session.getInputNames().isEmpty()) {
                this.inputName = session.getInputNames().iterator().next();
            } else {
                this.inputName = "inputs";
            }

            this.loaded = true;
            log.info("ONNX Model initialized successfully. Input Name: '{}', Inputs: {}, Outputs: {}",
                    inputName, session.getInputInfo().keySet(), session.getOutputInfo().keySet());

        } catch (Exception e) {
            log.error("Failed to initialize ONNX runtime session: {}", e.getMessage(), e);
            this.loaded = false;
        }
    }

    @Override
    public ModelInferenceResult predict(String url) {
        if (!loaded || session == null || env == null) {
            throw new ModelInferenceException("ONNX Runtime inference engine is unavailable or model failed to load.");
        }

        try {
            // Sklearn-onnx text classifier expects a string tensor with shape [1]
            try (OnnxTensor inputTensor = OnnxTensor.createTensor(env, new String[]{ url })) {
                Map<String, OnnxTensor> inputs = Collections.singletonMap(inputName, inputTensor);

                try (OrtSession.Result result = session.run(inputs)) {
                    // Extract label (long[])
                    long predictedClass = 0;
                    if (result.get("label").isPresent()) {
                        Object labelObj = result.get("label").get().getValue();
                        if (labelObj instanceof long[] arr && arr.length > 0) {
                            predictedClass = arr[0];
                        }
                    }

                    // Extract probabilities (float[][])
                    float probLegit = 0.5f;
                    float probPhishing = 0.5f;
                    if (result.get("probabilities").isPresent()) {
                        Object probObj = result.get("probabilities").get().getValue();
                        if (probObj instanceof float[][] probMatrix && probMatrix.length > 0 && probMatrix[0].length >= 2) {
                            probLegit = probMatrix[0][0];
                            probPhishing = probMatrix[0][1];
                        }
                    }

                    return new ModelInferenceResult(predictedClass, probLegit, probPhishing, true, null);
                }
            }
        } catch (Exception e) {
            log.error("Error executing model inference on URL '{}': {}", url, e.getMessage(), e);
            throw new ModelInferenceException("Inference failure: " + e.getMessage(), e);
        }
    }

    @PreDestroy
    public synchronized void close() {
        if (session != null) {
            try {
                session.close();
            } catch (Exception e) {
                log.warn("Error closing ONNX session: {}", e.getMessage());
            }
        }
        if (env != null) {
            try {
                env.close();
            } catch (Exception e) {
                log.warn("Error closing ONNX environment: {}", e.getMessage());
            }
        }
        this.loaded = false;
    }

    @Override
    public boolean isLoaded() {
        return loaded;
    }

    @Override
    public String getModelName() {
        return modelName;
    }

    @Override
    public String getModelVersion() {
        return modelVersion;
    }

    @Override
    public String getPublisherMetric() {
        return publisherMetric;
    }
}
