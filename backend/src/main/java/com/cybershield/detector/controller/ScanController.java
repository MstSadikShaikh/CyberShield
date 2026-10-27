package com.cybershield.detector.controller;

import com.cybershield.detector.dto.ScanRequestDto;
import com.cybershield.detector.dto.ScanResponseDto;
import com.cybershield.detector.dto.ScanSummaryDto;
import com.cybershield.detector.service.ScanService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/scans")
public class ScanController {

    private final ScanService scanService;

    public ScanController(ScanService scanService) {
        this.scanService = scanService;
    }

    /**
     * POST /api/v1/scans
     * Performs genuine ML-based phishing analysis on the submitted URL.
     */
    @PostMapping
    public ResponseEntity<ScanResponseDto> scanUrl(@Valid @RequestBody ScanRequestDto request) {
        ScanResponseDto response = scanService.scanUrl(request.getUrl());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * GET /api/v1/scans
     * Returns recent scan history up to the configured limit.
     */
    @GetMapping
    public ResponseEntity<List<ScanSummaryDto>> getRecentScans(
            @RequestParam(name = "limit", defaultValue = "20") int limit) {
        List<ScanSummaryDto> history = scanService.getRecentScans(limit);
        return ResponseEntity.ok(history);
    }

    /**
     * GET /api/v1/scans/{id}
     * Returns full scan details for a given record ID.
     */
    @GetMapping("/{id}")
    public ResponseEntity<ScanResponseDto> getScanById(@PathVariable Long id) {
        ScanResponseDto response = scanService.getScanById(id);
        return ResponseEntity.ok(response);
    }
}
