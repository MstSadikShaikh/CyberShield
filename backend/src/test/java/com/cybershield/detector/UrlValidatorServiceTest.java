package com.cybershield.detector;

import com.cybershield.detector.exception.InvalidUrlException;
import com.cybershield.detector.service.UrlValidatorService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

public class UrlValidatorServiceTest {

    private UrlValidatorService validator;

    @BeforeEach
    public void setUp() {
        validator = new UrlValidatorService();
    }

    @Test
    public void testValidHttpsUrl() {
        String result = validator.validateAndNormalize("https://www.example.com/login?ref=1");
        assertEquals("https://www.example.com/login?ref=1", result);
    }

    @Test
    public void testValidHttpUrl() {
        String result = validator.validateAndNormalize("http://sub.domain.org/path");
        assertEquals("http://sub.domain.org/path", result);
    }

    @Test
    public void testBareDomainAutoPrependsHttps() {
        String result = validator.validateAndNormalize("github.com/explore");
        assertEquals("https://github.com/explore", result);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "file:///etc/passwd",
            "javascript:alert('xss')",
            "data:text/html;base64,PHNjcmlwdD4=",
            "ftp://ftp.example.com/file.zip",
            "ws://socket.example.com/ws",
            "gopher://gopher.example.com",
            "about:blank"
    })
    public void testRejectUnsupportedSchemes(String unauthorizedUrl) {
        InvalidUrlException ex = assertThrows(InvalidUrlException.class, () -> {
            validator.validateAndNormalize(unauthorizedUrl);
        });
        assertTrue(ex.getMessage().contains("Unsupported URL scheme"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "",
            "   ",
            "http://",
            "https://",
            "https://invalid domain with spaces.com"
    })
    public void testRejectMalformedUrls(String malformed) {
        assertThrows(InvalidUrlException.class, () -> {
            validator.validateAndNormalize(malformed);
        });
    }

    @Test
    public void testRejectUrlExceedingMaxLength() {
        String longHost = "a".repeat(2050);
        String url = "https://" + longHost + ".com";
        assertThrows(InvalidUrlException.class, () -> {
            validator.validateAndNormalize(url);
        });
    }

    @Test
    public void testSanitizeSensitiveTokens() {
        String raw = "https://example.com/auth?token=supersecret123&session_id=abc987&api_key=key_xyz&user=john";
        String sanitized = validator.sanitizeForStorage(raw);

        assertFalse(sanitized.contains("supersecret123"));
        assertFalse(sanitized.contains("abc987"));
        assertFalse(sanitized.contains("key_xyz"));
        assertTrue(sanitized.contains("token=[REDACTED]"));
        assertTrue(sanitized.contains("session_id=[REDACTED]"));
        assertTrue(sanitized.contains("api_key=[REDACTED]"));
        assertTrue(sanitized.contains("user=john"));
    }
}
