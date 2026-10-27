package com.cybershield.detector;

import ai.onnxruntime.*;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Paths;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

public class ModelVerificationTest {

    @Test
    public void testModelInspectionAndInference() throws Exception {
        String modelPath = Paths.get("src", "main", "resources", "model", "model.onnx").toAbsolutePath().toString();
        File file = new File(modelPath);
        assertTrue(file.exists(), "model.onnx must exist at " + modelPath);

        System.out.println("Loading model from: " + modelPath);
        try (OrtEnvironment env = OrtEnvironment.getEnvironment();
             OrtSession session = env.createSession(modelPath, new OrtSession.SessionOptions())) {

            System.out.println("Model loaded successfully!");
            System.out.println("=== MODEL INPUT INFO ===");
            for (Map.Entry<String, NodeInfo> entry : session.getInputInfo().entrySet()) {
                System.out.println("Input Name: " + entry.getKey() + " -> " + entry.getValue().getInfo());
            }

            System.out.println("=== MODEL OUTPUT INFO ===");
            for (Map.Entry<String, NodeInfo> entry : session.getOutputInfo().entrySet()) {
                System.out.println("Output Name: " + entry.getKey() + " -> " + entry.getValue().getInfo());
            }

            // Test URLs: one legitimate and one known phishing test URL
            String[] testUrls = new String[] {
                    "https://www.google.com",
                    "https://clubedemilhagem.com/home.php",
                    "http://www.medicalnewstoday.com/articles/188939.php",
                    "http://paypal-security-update-account.com/login"
            };

            for (String url : testUrls) {
                // Sklearn-onnx pipelines usually expect a 1D or 2D array of strings
                // Shape: [1] (or [1, 1])
                OnnxTensor inputTensor = OnnxTensor.createTensor(env, new String[] { url });

                Map<String, OnnxTensor> inputs = Collections.singletonMap(session.getInputNames().iterator().next(), inputTensor);
                try (OrtSession.Result result = session.run(inputs)) {
                    System.out.println("\nTesting URL: " + url);
                    long[] labelArr = (long[]) result.get("label").get().getValue();
                    float[][] probArr = (float[][]) result.get("probabilities").get().getValue();
                    long predictedLabel = labelArr[0];
                    float probLegit = probArr[0][0];
                    float probPhishing = probArr[0][1];
                    System.out.println(String.format("  -> Predicted Label: %d, P(Legit): %.4f, P(Phishing): %.4f",
                            predictedLabel, probLegit, probPhishing));

                }
            }
        }
    }
}
