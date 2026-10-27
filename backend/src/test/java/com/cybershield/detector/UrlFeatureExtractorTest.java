package com.cybershield.detector;

import com.cybershield.detector.dto.UrlIndicatorDto;
import com.cybershield.detector.service.UrlFeatureExtractor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class UrlFeatureExtractorTest {

    private UrlFeatureExtractor extractor;

    @BeforeEach
    public void setUp() {
        extractor = new UrlFeatureExtractor();
    }

    @Test
    public void testDetectIpAddressHost() {
        List<UrlIndicatorDto> indicators = extractor.extractIndicators("http://192.168.1.100/admin");
        boolean ipFound = indicators.stream().anyMatch(i -> "Host Type".equals(i.getName()) && "DANGER".equals(i.getSeverity()));
        assertTrue(ipFound, "Should flag raw IP address as DANGER");
    }

    @Test
    public void testDetectUserinfoAtSymbolSpoofing() {
        List<UrlIndicatorDto> indicators = extractor.extractIndicators("https://google.com@attacker-site.com/login");
        boolean atFound = indicators.stream().anyMatch(i -> "URL Obfuscation".equals(i.getName()) && "DANGER".equals(i.getSeverity()));
        assertTrue(atFound, "Should flag '@' symbol spoofing as DANGER");
    }

    @Test
    public void testDetectSuspiciousKeywords() {
        List<UrlIndicatorDto> indicators = extractor.extractIndicators("https://secure-login-verify-account.com/webscr");
        boolean kwFound = indicators.stream().anyMatch(i -> "Sensitive Keywords".equals(i.getName()));
        assertTrue(kwFound, "Should identify phishing keywords");
    }

    @Test
    public void testDetectMultipleSubdomains() {
        List<UrlIndicatorDto> indicators = extractor.extractIndicators("https://a.b.c.d.bank.com/portal");
        boolean subFound = indicators.stream().anyMatch(i -> "Subdomain Depth".equals(i.getName()) && "WARNING".equals(i.getSeverity()));
        assertTrue(subFound, "Should warn on deep subdomain nesting");
    }

    @Test
    public void testEntropyCalculation() {
        double lowEntropy = extractor.calculateShannonEntropy("aaaaaa");
        double highEntropy = extractor.calculateShannonEntropy("7f9b2a1c8d4e0f");
        assertTrue(lowEntropy < 1.0, "Repetitive string should have near zero entropy");
        assertTrue(highEntropy > 3.0, "Random hex string should have high entropy");
    }
}
