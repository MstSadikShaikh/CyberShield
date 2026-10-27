package com.cybershield.detector;

import com.cybershield.detector.controller.ScanController;
import com.cybershield.detector.dto.ScanRequestDto;
import com.cybershield.detector.dto.ScanResponseDto;
import com.cybershield.detector.dto.ScanSummaryDto;
import com.cybershield.detector.exception.GlobalExceptionHandler;
import com.cybershield.detector.exception.ResourceNotFoundException;
import com.cybershield.detector.service.ScanService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
public class ScanControllerTest {

    private MockMvc mockMvc;

    @Mock
    private ScanService scanService;

    private ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    public void setUp() {
        ScanController controller = new ScanController(scanService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    public void testScanValidUrlReturnsCreated() throws Exception {
        ScanResponseDto mockResponse = new ScanResponseDto();
        mockResponse.setId(1L);
        mockResponse.setSubmittedUrl("https://example.com");
        mockResponse.setSanitizedUrl("https://example.com");
        mockResponse.setPrediction("LEGITIMATE");
        mockResponse.setRiskScore(5.0);
        mockResponse.setRiskLevel("LOW");
        mockResponse.setModelVersion("pirocheto-linear-svm-v1.0");
        mockResponse.setScannedAt(Instant.now());

        when(scanService.scanUrl(anyString())).thenReturn(mockResponse);

        ScanRequestDto request = new ScanRequestDto("https://example.com");

        mockMvc.perform(post("/api/v1/scans")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.prediction").value("LEGITIMATE"))
                .andExpect(jsonPath("$.riskScore").value(5.0))
                .andExpect(jsonPath("$.riskLevel").value("LOW"));
    }

    @Test
    public void testScanBlankUrlReturnsBadRequest() throws Exception {
        ScanRequestDto request = new ScanRequestDto("");

        mockMvc.perform(post("/api/v1/scans")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").value("Validation Error"));
    }

    @Test
    public void testGetRecentScans() throws Exception {
        ScanSummaryDto item = new ScanSummaryDto(
                1L, "https://test.com", "PHISHING", 95.0, "CRITICAL", Instant.now()
        );
        when(scanService.getRecentScans(anyInt())).thenReturn(List.of(item));

        mockMvc.perform(get("/api/v1/scans?limit=10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].prediction").value("PHISHING"))
                .andExpect(jsonPath("$[0].riskScore").value(95.0));
    }

    @Test
    public void testGetScanByIdNotFound() throws Exception {
        when(scanService.getScanById(999L)).thenThrow(new ResourceNotFoundException("Scan record not found"));

        mockMvc.perform(get("/api/v1/scans/999"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404));
    }
}
