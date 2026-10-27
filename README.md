# CyberShield — Tri-Pillar Hybrid Phishing URL Detector

[![Java](https://img.shields.io/badge/Java-21%20LTS-007396?logo=openjdk&logoColor=white)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.3.4-6DB33F?logo=springboot&logoColor=white)](https://spring.io/projects/spring-boot)
[![ONNX Runtime](https://img.shields.io/badge/ONNX%20Runtime-Java%201.19.2-005CED?logo=onnx&logoColor=white)](https://onnxruntime.ai/)
[![Google Gemini](https://img.shields.io/badge/Google%20Gemini-3.8%20Flash-8E75B2?logo=google&logoColor=white)](https://ai.google.dev/)
[![Threat Intelligence](https://img.shields.io/badge/Google%20Web%20Risk-API-EA4335?logo=googlecloud&logoColor=white)](https://cloud.google.com/web-risk)
[![MySQL](https://img.shields.io/badge/MySQL-8.0-4479A1?logo=mysql&logoColor=white)](https://www.mysql.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-5.4-646CFF?logo=vite&logoColor=white)](https://vitejs.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **CyberShield** is an enterprise-grade cybersecurity web application that combines local machine-learning inference, live threat intelligence telemetry, and secondary AI adjudication to identify deceptive and malicious web destinations.
> Built with a **Java 21 Spring Boot** backend, native **ONNX Runtime** inference, optional **Google Web Risk API** threat intelligence, optional **Google Gemini API** qualitative analysis, persistent **MySQL** audit logging, and a modern **React JS** frontend.

---

## Table of Contents
1. [Overview & Tri-Pillar Architecture](#1-overview--tri-pillar-architecture)
2. [Evidence Combination & Decision Rules](#2-evidence-combination--decision-rules)
3. [The ChatGPT False-Positive Investigation](#3-the-chatgpt-false-positive-investigation)
4. [Model Provenance & Metrics Distinction](#4-model-provenance--metrics-distinction)
5. [Threat Intelligence Integration (Google Web Risk)](#5-threat-intelligence-integration-google-web-risk)
6. [Gemini API Secondary Analysis](#6-gemini-api-secondary-analysis)
7. [Environment Variables & Configuration](#7-environment-variables--configuration)
8. [Database Schema & Migrations](#8-database-schema--migrations)
9. [REST API Documentation & Schemas](#9-rest-api-documentation--schemas)
10. [Automated Testing (60 Passing Tests)](#10-automated-testing-60-passing-tests)
11. [Local Development & Quick Start](#11-local-development--quick-start)
12. [Security, Privacy & Safe Execution Policies](#12-security-privacy--safe-execution-policies)
13. [Deployment Guide (Vercel & Cloud Backend)](#13-deployment-guide)
14. [Licenses & Attributions](#14-licenses--attributions)

---

## 1. Overview & Tri-Pillar Architecture

Modern phishing campaigns employ lookalike characters, brand hijacking, high-entropy dynamic domain generation, and legitimate hosting providers to evade simple static blocklists. Conversely, standalone machine-learning models frequently misclassify novel, short, or uncommon brand names because their vocabulary is locked to their training snapshot.

CyberShield implements a **Tri-Pillar Hybrid Architecture** that combines three distinct detection disciplines without blindly averaging their scores:

```
                                  [ User Submits URL ]
                                           │
                                           ▼
                     [ React 18 Frontend / Vite / Vanilla CSS ]
                                           │ (HTTP POST /api/v1/scans)
                                           ▼
                      [ Spring Boot 3.3.4 (Java 21 LTS) ]
                 ┌─────────────────────────┴─────────────────────────┐
                 │ 1. Scheme Validation (http / https only)          │
                 │ 2. Query Parameter & Credential Redaction         │
                 │ 3. Heuristic Feature Extraction (Entropy, Depth)  │
                 └─────────────────────────┬─────────────────────────┘
                                           │
        ┌──────────────────────────────────┼──────────────────────────────────┐
        ▼                                  ▼                                  ▼
 ┌───────────────┐                  ┌───────────────┐                  ┌───────────────┐
 │   PILLAR 1    │                  │   PILLAR 2    │                  │   PILLAR 3    │
 │   Local ML    │                  │ Threat Intel  │                  │   Gemini AI   │
 │ (ONNX Linear  │                  │  (Web Risk    │                  │  (Secondary   │
 │   SVM Model)  │                  │   REST API)   │                  │  Adjudicator) │
 └───────┬───────┘                  └───────┬───────┘                  └───────┬───────┘
         │                                  │                                  │
         │ (Raw Prob)                       │ (Confirmed Match / No Match)     │ (Syntactic Review)
         └──────────────────────────────────┼──────────────────────────────────┘
                                            │
                                            ▼
                       [ Hybrid Evidence Orchestrator ]
                     (Transparent, Non-Averaged Rules)
                                            │
                                            ▼
                     [ MySQL 8.0 Relational Persistence ]
                        (Redacted URL, Disclosures, ID)
                                            │
                                            ▼
                        [ JSON Response to Frontend ]
                   (Verdict, Scores, Tri-Pillar Breakdown)
```

---

## 2. Evidence Combination & Decision Rules

A common architectural anti-pattern is blindly averaging model probabilities with heuristic weights and threat-feed flags. CyberShield strictly enforces **transparent, non-averaged defensive decision rules**:

| Scenario | Condition | Decision Logic | Final Classification | Risk Level |
|---|---|---|---|---|
| **A. Confirmed Threat Match** | Google Web Risk returns `MATCH_FOUND` | Threat signatures take immediate precedence over ML probabilities. | `CONFIRMED_THREAT` | **CRITICAL** (95–100) |
| **B. Decisive High-Risk ML** | ML probability $\ge 0.75$, or $\ge 0.60$ with supporting heuristic warnings | ML model identifies malicious n-grams corroborated by structural heuristics. | `HIGH_RISK_ML` | **HIGH / CRITICAL** (75–100) |
| **C. Conflicting Evidence (ChatGPT Pattern)** | ML probability in 50–75% range, but **zero** heuristic threat indicators, and threat feed is clean | Baseline ML disagrees with structural checks. Disagreement is documented. In accordance with defensive safety rules, a qualitative LLM opinion alone cannot prove a URL legitimate over an ML detection; the link is classified conservatively as UNCERTAIN. | `CONFLICT_EVIDENCE_UNCERTAIN` or `CONFLICT_UNRESOLVED` | **MEDIUM** (45–50) |
| **D. Uncertain ML Output** | ML probability in the borderline 40–65% range | Secondary Gemini analysis is requested. If Gemini detects deceptive patterns $\rightarrow$ elevated to `AI_ELEVATED` (HIGH/CRITICAL); if Gemini observes standard structure $\rightarrow$ kept defensively as `AI_UNCERTAIN` (MEDIUM, score 40) rather than proving legitimacy. | `AI_ELEVATED` or `AI_UNCERTAIN` | **HIGH** or **MEDIUM** |
| **E. Clean / Legitimate ML** | ML probability $< 0.40$ with clean heuristics and no threat match | Lexical features align with standard web patterns. | `LOW_RISK_LEGITIMATE` | **LOW** (0–39) |
| **F. Provider Unconfigured** | Gemini or Web Risk credentials omitted | Scanner falls back entirely to local ONNX model and heuristics; explicit disclosure added to `limitations`. | Local ML result | According to ML |
| **G. Model Unavailable** | ONNX runtime failure or missing model | Refuses to fabricate a prediction. Returns UNCERTAIN unless verified threat match supports warning. | `MODEL_UNAVAILABLE` | **MEDIUM** (50) |

---

## 3. The ChatGPT False-Positive Investigation

### Problem Statement
When scanning `https://chatgpt.com/`, earlier versions of the classifier produced a false positive:
- Raw ONNX Model Output: `predictedClass = 1` (Phishing), `modelProbability = 0.6226` (62.3% uncalibrated model-reported likelihood).
- Structural Heuristics: Zero threat indicators (HTTPS encryption, registered domain, 0 subdomains, normal entropy of 3.10 bits/char, standard URL length of 20 characters).
- Prior Flaw: The previous risk assessment formula assigned `PHISHING` solely because `predictedClass == 1 && score >= 60.0`, triggering an embarrassing false alarm on one of the world's most popular domains.

### Root Cause
The pretrained model (`pirocheto/phishing-url-detection`) is a static LinearSVM trained on datasets prior to late 2022. Because `chatgpt.com` was not in its training vocabulary, its character n-grams produced a borderline statistical score (~62%) without understanding the entity.

### Solution Without Hardcoding Domain Allowlists
Hardcoding `chatgpt.com` into an allowlist is an anti-pattern that hides model flaws and fails on the next novel brand. Instead, CyberShield implements **principled conflict arbitration**:
1. **Conflict Detection:** When `predictedClass == 1` but `dangerCount == 0 && warningCount == 0`, the system detects an evidence conflict.
2. **Defensive Safety Rule:** Gemini secondary review or structural heuristics can identify that the domain syntax is standard and clean. However, a qualitative LLM opinion alone **must never prove a URL legitimate** or completely overturn a machine-learning phishing alert.
3. **Conservative UNCERTAIN Verdict:** CyberShield assigns `prediction = "UNCERTAIN"`, `finalAssessment = "CONFLICT_EVIDENCE_UNCERTAIN"`, and `riskScore = 45.0` (`MEDIUM` risk level).
4. **Transparent Audit:** The disagreement between the uncalibrated ML score and clean structural indicators is comprehensively documented in the response explanation and audit history.

---

## 4. Model Provenance & Metrics Distinction

To maintain scientific and ethical integrity, CyberShield strictly distinguishes between the different evidence tiers:

1. **Publisher-Reported Metrics (Static Benchmark):**
   - Source: Hugging Face repository [`pirocheto/phishing-url-detection`](https://huggingface.co/pirocheto/phishing-url-detection).
   - Algorithm: Scikit-learn LinearSVM Pipeline with TF-IDF Vectorizer.
   - Publisher-Claimed Accuracy: **~94.86%** on held-out test splits.
   - *Limitation:* Measures performance strictly against static, historical URL datasets.
2. **Empirically Measured Observations (Our Workspace Evaluation):**
   - Correctly identifies obvious credential harvesters (e.g., `http://paypal-security-update-account.com/login` $\rightarrow$ 100.0% Phishing).
   - Correctly identifies standard popular domains (e.g., `google.com` $\rightarrow$ 0.4%, `wikipedia.org` $\rightarrow$ 0.0%).
   - Susceptible to false positives on short modern brand names absent from training data (e.g., `chatgpt.com` $\rightarrow$ 62.3% raw probability).
3. **Gemini Secondary Analysis (Qualitative Assessment):**
   - Provides qualitative linguistic analysis of syntactic patterns.
   - *Important:* A Gemini qualitative assessment is **never** presented as a calibrated statistical probability or a verified threat blacklist match.
4. **Threat Intelligence Matches (Deterministic Telemetry):**
   - Represents verified matches against Google Web Risk threat databases.
5. **No Claims of Higher Accuracy:**
   - We do **not** claim that the combined hybrid system achieves higher aggregate statistical accuracy until systematically demonstrated on a labeled, independently validated benchmark dataset.

---

## 5. Threat Intelligence Integration (Google Web Risk)

CyberShield integrates with the **Google Web Risk API v1** via a modular Java service abstraction (`ThreatIntelligenceService` / `GoogleWebRiskThreatService`).

### Provider Capabilities
- **Endpoint:** `GET https://webrisk.googleapis.com/v1/uris:search`
- **Threat Categories Monitored:**
  - `SOCIAL_ENGINEERING` (Phishing, deceptive brand spoofing)
  - `MALWARE` (Harmful software payloads)
  - `UNWANTED_SOFTWARE` (Deceptive or intrusive software)
- **Data Minimization:** Query parameters, tokens, and fragments are stripped using `urlValidatorService.stripQueryAndFragment(url)` before sending.
- **Passive Telemetry:** CyberShield never visits, crawls, or opens network sockets to the target domain.

### Negative Lookup Semantics
- When Google Web Risk returns an empty object `{}`:
  - CyberShield records status `NO_MATCH`.
  - Details explicitly state: *"No active threat signature recorded in threat feed. (Note: does not guarantee the URL is safe)."*
  - The UI will **never** display a green "Safe" badge solely because a threat intelligence check returned no match.

---

## 6. Gemini API Secondary Analysis

CyberShield utilizes Google's **Gemini API** as an optional, secondary adjudicator (`GeminiAnalysisService`).

### Configuration & Quota Management
- Default model: `gemini-3.8-flash` (configurable via `GEMINI_MODEL`).
- Cost & Quota Optimization: Gemini is **not** called on every scan. It is invoked only when:
  1. The ONNX ML model probability falls within the uncertain zone (40–65%).
  2. The ONNX prediction conflicts with structural heuristics (e.g., `chatgpt.com`).
  3. `cybershield.gemini.always-run` is explicitly set to `true`.

### Security Directives & Prompt Isolation
- All hostnames and URL tokens are treated strictly as **untrusted data**.
- Explicit prompt instructions prohibit Gemini from executing instructions embedded in URL text or inventing domain registration dates, TLS details, or website content.
- Response Schema:
  ```json
  {
    "assessment": "SUSPICIOUS | NOT_OBVIOUSLY_SUSPICIOUS | INSUFFICIENT_EVIDENCE",
    "indicators": ["short, observable findings"],
    "explanation": "concise plain-language reasoning (< 400 chars)",
    "limitations": ["limitations regarding passive lexical analysis"]
  }
  ```
- Strict Java Validation: Output enums, string lengths (max 500 chars), and list sizes (max 10 items) are strictly validated and constrained in Java.

---

## 7. Environment Variables & Configuration

Configuration is managed via server-side environment variables or `application.properties`. **Never expose API keys to the frontend or git commits.**

### Backend Configuration (`backend/src/main/resources/application.properties`)

| Environment Variable | Property Key | Default Value | Description |
|---|---|---|---|
| `PORT` | `server.port` | `8080` | Backend HTTP listening port |
| `DB_HOST` | `spring.datasource.url` | `localhost` | MySQL server hostname |
| `DB_PORT` | — | `3306` | MySQL port |
| `DB_NAME` | — | `cybershield` | MySQL database name |
| `DB_USER` | `spring.datasource.username` | `root` | MySQL database user |
| `DB_PASSWORD` | `spring.datasource.password` | `""` | MySQL database password |
| `GEMINI_ENABLED` | `cybershield.gemini.enabled` | `false` | Enable/disable Gemini secondary analysis |
| `GEMINI_API_KEY` | `cybershield.gemini.api-key` | `""` | Google AI Studio Gemini API Key |
| `GEMINI_MODEL` | `cybershield.gemini.model` | `gemini-3.8-flash` | Gemini model identifier |
| `GEMINI_TIMEOUT_SECONDS` | `cybershield.gemini.timeout-seconds` | `5` | HTTP request timeout in seconds |
| `THREAT_INTELLIGENCE_ENABLED` | `cybershield.threat-intel.enabled` | `false` | Enable/disable Threat Intelligence |
| `THREAT_INTELLIGENCE_API_KEY` | `cybershield.threat-intel.api-key` | `""` | Google Cloud Web Risk API Key |
| `THREAT_INTELLIGENCE_TIMEOUT_SECONDS` | `cybershield.threat-intel.timeout-seconds` | `4` | Web Risk HTTP timeout in seconds |
| `CORS_ALLOWED_ORIGINS` | `cybershield.cors.allowed-origins` | `http://localhost:5173,...` | Allowed CORS origins |

### How to Configure API Keys Locally
1. **Google Gemini:** Obtain a free API key from [Google AI Studio](https://aistudio.google.com/).
2. **Google Web Risk:** Enable the Web Risk API in [Google Cloud Console](https://console.cloud.google.com/) and generate an API key.
3. In PowerShell, export environment variables before launching the backend:
   ```powershell
   $env:GEMINI_ENABLED = "true"
   $env:GEMINI_API_KEY = "your_gemini_api_key_here"
   $env:THREAT_INTELLIGENCE_ENABLED = "true"
   $env:THREAT_INTELLIGENCE_API_KEY = "your_webrisk_api_key_here"
   ```

---

## 8. Database Schema & Migrations

Database name: `cybershield`. The schema preserves backward compatibility with older scan records.

```sql
CREATE DATABASE IF NOT EXISTS cybershield
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE cybershield;

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
    -- Hybrid Detection Fields (Safe Migration)
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
```

---

## 9. REST API Documentation & Schemas

### Endpoints

#### 1. Scan URL
- **Method:** `POST /api/v1/scans`
- **Request:**
  ```json
  {
    "url": "https://chatgpt.com/"
  }
  ```
- **Response (`201 Created`):**
  ```json
  {
    "id": 11,
    "submittedUrl": "https://chatgpt.com/",
    "sanitizedUrl": "https://chatgpt.com/",
    "prediction": "UNCERTAIN",
    "riskScore": 50.0,
    "riskLevel": "MEDIUM",
    "modelVersion": "pirocheto-linear-svm-v1.0",
    "modelProbability": 0.6225845,
    "modelAssessment": "PHISHING (62.3%)",
    "finalAssessment": "CONFLICT_UNRESOLVED",
    "explanation": "The ML model predicted phishing likelihood (62%), but zero structural or lexical threat indicators were detected. Secondary AI analysis was not configured to adjudicate. Classified conservatively as UNCERTAIN.",
    "precautions": [
      "Verify the domain name character-by-character to prevent typosquatting and lookalike attacks.",
      "Navigate to the service directly via a bookmark or search engine rather than clicking unsolicited links."
    ],
    "indicators": [
      {
        "name": "Transport Encryption",
        "value": "HTTPS (TLS)",
        "severity": "SAFE",
        "description": "Connection is encrypted in transit."
      },
      {
        "name": "Host Type",
        "value": "Domain Name (chatgpt.com)",
        "severity": "SAFE",
        "description": "Host uses a registered domain name."
      }
    ],
    "limitations": [
      "Analysis is based on passive lexical, structural, and threat-feed indicators without active network crawling.",
      "Threat intelligence provider is not configured; scan relied on local ML and heuristics.",
      "Secondary AI provider is unconfigured; conflicting ML and heuristic signals could not be independently arbitrated."
    ],
    "threatIntelligence": {
      "status": "NOT_CONFIGURED",
      "source": "Google Web Risk API",
      "threatMatches": [],
      "details": "Threat intelligence lookup is not enabled or API credentials are not configured.",
      "checkedAt": "2026-10-27T13:59:48Z"
    },
    "geminiAnalysis": {
      "status": "NOT_CONFIGURED",
      "assessment": "NOT_PERFORMED",
      "indicators": [],
      "explanation": "Gemini secondary analysis is not enabled or GEMINI_API_KEY is not configured.",
      "limitations": ["Secondary AI analysis disabled; relying on local ML model and heuristics."],
      "providerModel": "gemini-3.8-flash"
    },
    "scannedAt": "2026-10-27T13:59:48Z"
  }
  ```

#### 2. Get Recent Scans
- **Method:** `GET /api/v1/scans?limit=10`
- **Response (`200 OK`):** Returns array of `ScanSummaryDto` objects bounded by `max-limit`.

#### 3. Health & Diagnostic Probe
- **Method:** `GET /api/v1/health`
- **Response (`200 OK`):** Returns status `UP`, `modelStatus: READY`, and `databaseStatus: CONNECTED`.

---

## 10. Automated Testing (60 Passing Tests)

CyberShield includes a test suite covering all services, mocks, failure modes, and regression URLs.

```bash
cd backend
./mvnw test
```

### Test Suite Summary: 60 Tests, 0 Failures

1. **`RegressionUrlsTest` (4 tests):**
   - `chatgpt.com`: Documents raw ONNX output (~62%), zero heuristic threat indicators, and proves conservative UNCERTAIN resolution (`CONFLICT_EVIDENCE_UNCERTAIN`, score 45.0).
   - `google.com`: Verifies clean output (0.4% uncalibrated model likelihood).
   - `en.wikipedia.org`: Verifies legitimate output (0.0% uncalibrated model likelihood).
   - `synthetic-phishing`: Proves high-confidence detection (99.99%) on malicious patterns without network navigation.
2. **`GeminiAnalysisServiceTest` (9 tests):**
   - Tests disabled state, missing API key, placeholder key rejection.
   - Tests JSON response parsing using mocked HTTP exchanges.
   - Tests HTTP 404 (model not found / deprecated model name fallback).
   - Tests HTTP 401/403 authentication error handling.
   - Tests HTTP 400 bad request handling.
   - Tests HTTP 429 quota exhaustion and timeouts.
   - Tests invalid enum fallback to `INSUFFICIENT_EVIDENCE`.
   - Proves secrets are never leaked into responses or logs.
3. **`ThreatIntelligenceServiceTest` (6 tests):**
   - Tests unconfigured state.
   - Tests confirmed match (`MATCH_FOUND`) parsing threat types.
   - Tests negative lookup (`NO_MATCH`), verifying that clean results are not falsely labeled as proof of safety.
   - Tests timeout and quota error handling.
4. **`HybridAssessmentOrchestrationTest` (5 tests):**
   - Proves confirmed threat intelligence match overrides ML and heuristics to `CRITICAL`.
   - Proves conflict arbitration with Gemini benign opinion preserves conservative `UNCERTAIN` (`CONFLICT_EVIDENCE_UNCERTAIN`) and never certifies legitimacy alone.
   - Proves conflict arbitration without Gemini defaults to `UNCERTAIN (MEDIUM)`.
   - Tests uncertain ML elevation with Gemini.
   - Tests model unavailable fallback.
5. **`ModelVerificationTest` (1 test):** Direct ONNX tensor shape and input/output verification.
6. **`UrlValidatorServiceTest` (17 tests):** Comprehensive input validation, scheme constraints, and parameter scrubbing.
7. **`UrlFeatureExtractorTest` (5 tests):** Shannon entropy, userinfo `@` spoofing, keyword extraction, and IP host analysis.
8. **`RiskAssessmentServiceTest` (4 tests):** Backward-compatible baseline assessment logic.
9. **`ScanControllerTest` (4 tests):** MockMvc endpoint and error handling tests.
10. **`HealthControllerTest` (2 tests):** System uptime and dependency health probes.

---

## 11. Local Development & Quick Start

### Prerequisites
- **JDK 21 LTS** (`java -version`)
- **Node.js 18+** & **npm** (`node -v`)
- **MySQL 8.0+** running on `localhost:3306`

### Running the Full Application
1. **Initialize MySQL Database:**
   ```bash
   mysql -u root -p < schema.sql
   ```
2. **Start Backend (Port 8080):**
   ```bash
   cd backend
   ./mvnw spring-boot:run
   ```
3. **Start Frontend (Port 5173):**
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
4. Open your browser at `http://localhost:5173/`.

---

## 12. Security, Privacy & Safe Execution Policies

1. **Passive Analysis Only:** CyberShield strictly parses, tokenizes, and extracts lexical features from URL strings. It **never** visits, navigates to, or fetches submitted links.
2. **Strict Protocol Whitelist:** Only `http://` and `https://` schemes are accepted. Attacks utilizing `file:`, `javascript:`, `data:`, or loopback addresses are blocked at validation.
3. **Sensitive Query Parameter Redaction:** URL credentials (e.g. `token=`, `key=`, `password=`, `jwt=`) are automatically stripped before storage and before any external API transmission.
4. **Zero Frontend Secret Exposure:** Neither `GEMINI_API_KEY` nor `THREAT_INTELLIGENCE_API_KEY` are ever embedded in React code, sent to the browser, or committed to git.
5. **No Blind Trust / No Domain Allowlisting:** Neither `chatgpt.com` nor any popular domain is hardcoded in an allowlist. All domains undergo genuine lexical and heuristic analysis.

---

## 13. Deployment Guide

### Frontend Deployment (Vercel)
1. Import repository into [Vercel](https://vercel.com/).
2. Root Directory: `frontend`. Framework: **Vite**.
3. Environment Variable: `VITE_API_BASE_URL` pointing to your deployed Spring Boot URL.
4. Deploy! `frontend/vercel.json` ensures clean client-side routing.

### Backend Deployment (Java Cloud Host)
1. Provision MySQL database (Railway, AWS RDS, or Render).
2. Set environment variables: `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `CORS_ALLOWED_ORIGINS`.
3. Optionally configure `GEMINI_API_KEY` and `THREAT_INTELLIGENCE_API_KEY`.
4. Deploy using standard Java 21 container:
   ```bash
   mvn clean package -DskipTests
   java -jar target/cybershield-backend-1.0.0.jar
   ```

---

## 14. Licenses & Attributions

- **CyberShield:** [MIT License](LICENSE)
- **Pretrained ONNX Model:** `pirocheto/phishing-url-detection` — [MIT License](https://huggingface.co/pirocheto/phishing-url-detection)
- **ONNX Runtime:** Microsoft Corporation — [MIT License](https://github.com/microsoft/onnxruntime/blob/main/LICENSE)
- **Google Web Risk & Gemini APIs:** Google LLC — [Google Cloud Platform Terms](https://cloud.google.com/terms)
- **Spring Boot:** VMware / Broadcom — [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
- **Lucide Icons:** Lucide Contributors — [ISC License](https://lucide.dev/license)
