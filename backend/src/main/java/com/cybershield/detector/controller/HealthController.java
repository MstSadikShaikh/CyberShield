package com.cybershield.detector.controller;

import com.cybershield.detector.dto.HealthResponseDto;
import com.cybershield.detector.service.ModelInferenceService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.lang.management.ManagementFactory;
import java.sql.Connection;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/health")
public class HealthController {

    private static final Logger log = LoggerFactory.getLogger(HealthController.class);

    private final ModelInferenceService modelInferenceService;
    private final DataSource dataSource;
    private final long startTimeMillis;

    public HealthController(ModelInferenceService modelInferenceService, DataSource dataSource) {
        this.modelInferenceService = modelInferenceService;
        this.dataSource = dataSource;
        this.startTimeMillis = System.currentTimeMillis();
    }

    /**
     * GET /api/v1/health
     * Comprehensive health check reporting service status, ML engine state, and DB connectivity.
     */
    @GetMapping
    public ResponseEntity<HealthResponseDto> getHealth() {
        HealthResponseDto health = new HealthResponseDto();
        health.setTimestamp(Instant.now());
        health.setModelName(modelInferenceService.getModelName());
        health.setModelVersion(modelInferenceService.getModelVersion());
        health.setPublisherMetric(modelInferenceService.getPublisherMetric());

        boolean modelUp = modelInferenceService.isLoaded();
        health.setModelStatus(modelUp ? "READY" : "FAILED");

        // Safely test database connectivity without exposing connection secrets
        String dbStatus = "DISCONNECTED";
        try (Connection conn = dataSource.getConnection()) {
            if (conn.isValid(2)) {
                dbStatus = "CONNECTED";
            }
        } catch (Exception e) {
            log.debug("Database health probe: MySQL not reachable ({})", e.getMessage());
            dbStatus = "DISCONNECTED";
        }
        health.setDatabaseStatus(dbStatus);

        long uptime = (System.currentTimeMillis() - startTimeMillis) / 1000;
        health.setUptimeSeconds(uptime);

        // System overall status
        if (modelUp) {
            health.setStatus("UP");
        } else {
            health.setStatus("DEGRADED");
        }

        Map<String, Object> details = new HashMap<>();
        details.put("jvmVersion", System.getProperty("java.version"));
        details.put("availableProcessors", Runtime.getRuntime().availableProcessors());
        details.put("freeMemoryMb", Runtime.getRuntime().freeMemory() / (1024 * 1024));
        details.put("maxMemoryMb", Runtime.getRuntime().maxMemory() / (1024 * 1024));
        health.setDetails(details);

        return ResponseEntity.ok(health);
    }
}
