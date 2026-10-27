-- ===================================================================
-- CyberShield Database Initialization Script
-- Target Database: MySQL 8.0+
-- Database Name: cybershield
-- ===================================================================

CREATE DATABASE IF NOT EXISTS cybershield
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE cybershield;

-- Table: scan_history
-- Stores audit records of scanned URLs, ML inference output, Threat Intelligence matches,
-- Gemini secondary analysis, heuristic indicators, and defensive recommendations.
CREATE TABLE IF NOT EXISTS scan_history (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    submitted_url VARCHAR(2048) NOT NULL,
    sanitized_url VARCHAR(2048) NOT NULL,
    prediction VARCHAR(20) NOT NULL,
    risk_score DOUBLE NOT NULL,
    risk_level VARCHAR(20) NOT NULL,
    model_version VARCHAR(100) NOT NULL,
    model_probability DOUBLE DEFAULT NULL,
    explanation TEXT,
    indicators_json TEXT,
    precautions_json TEXT,
    scanned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Hybrid Detection Enhancements
    threat_intel_status VARCHAR(50) DEFAULT 'NOT_CONFIGURED',
    threat_intel_source VARCHAR(100) DEFAULT NULL,
    threat_categories_json TEXT DEFAULT NULL,
    gemini_status VARCHAR(50) DEFAULT 'NOT_CONFIGURED',
    gemini_model VARCHAR(100) DEFAULT NULL,
    gemini_assessment_json TEXT DEFAULT NULL,
    final_assessment VARCHAR(50) DEFAULT NULL,
    INDEX idx_scanned_at (scanned_at DESC),
    INDEX idx_prediction (prediction),
    INDEX idx_risk_level (risk_level),
    INDEX idx_final_assessment (final_assessment)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
