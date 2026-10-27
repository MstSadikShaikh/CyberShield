package com.cybershield.detector.exception;

public class ModelInferenceException extends RuntimeException {

    public ModelInferenceException(String message) {
        super(message);
    }

    public ModelInferenceException(String message, Throwable cause) {
        super(message, cause);
    }
}
