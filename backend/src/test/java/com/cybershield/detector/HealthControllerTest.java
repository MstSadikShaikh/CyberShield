package com.cybershield.detector;

import com.cybershield.detector.controller.HealthController;
import com.cybershield.detector.service.ModelInferenceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import javax.sql.DataSource;
import java.sql.Connection;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
public class HealthControllerTest {

    private MockMvc mockMvc;

    @Mock
    private ModelInferenceService modelInferenceService;

    @Mock
    private DataSource dataSource;

    @Mock
    private Connection connection;

    @BeforeEach
    public void setUp() {
        HealthController controller = new HealthController(modelInferenceService, dataSource);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    public void testHealthEndpointReturnsUpWhenModelLoaded() throws Exception {
        when(modelInferenceService.isLoaded()).thenReturn(true);
        when(modelInferenceService.getModelName()).thenReturn("Pirocheto LinearSVM ONNX URL Classifier");
        when(modelInferenceService.getModelVersion()).thenReturn("pirocheto-linear-svm-v1.0");
        when(modelInferenceService.getPublisherMetric()).thenReturn("94.86% Reported Accuracy");

        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.isValid(anyInt())).thenReturn(true);

        mockMvc.perform(get("/api/v1/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.modelStatus").value("READY"))
                .andExpect(jsonPath("$.databaseStatus").value("CONNECTED"))
                .andExpect(jsonPath("$.modelVersion").value("pirocheto-linear-svm-v1.0"));
    }

    @Test
    public void testHealthEndpointGracefulWhenDatabaseDisconnected() throws Exception {
        when(modelInferenceService.isLoaded()).thenReturn(true);
        when(dataSource.getConnection()).thenThrow(new RuntimeException("Connection refused"));

        mockMvc.perform(get("/api/v1/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.databaseStatus").value("DISCONNECTED"));
    }
}
