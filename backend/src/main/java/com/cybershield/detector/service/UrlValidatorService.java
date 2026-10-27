package com.cybershield.detector.service;

import com.cybershield.detector.exception.InvalidUrlException;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

@Service
public class UrlValidatorService {

    private static final int MAX_URL_LENGTH = 2048;
    private static final Pattern SENSITIVE_PARAM_PATTERN = Pattern.compile(
            "(?i)(token|key|password|pass|secret|auth|access_token|api_key|session_id|jwt|code|credit_card|cvv)=([^&]*)"
    );

    // List of blacklisted URI schemes
    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");

    /**
     * Validates that the input URL adheres to strict safety, length, and scheme standards.
     * Throws InvalidUrlException if invalid.
     */
    public String validateAndNormalize(String rawUrl) {
        if (rawUrl == null || rawUrl.trim().isEmpty()) {
            throw new InvalidUrlException("URL cannot be empty.");
        }

        String trimmed = rawUrl.trim();

        if (trimmed.length() > MAX_URL_LENGTH) {
            throw new InvalidUrlException("URL length (" + trimmed.length() + ") exceeds maximum limit of " + MAX_URL_LENGTH + " characters.");
        }

        // Check for null bytes or control characters
        for (char c : trimmed.toCharArray()) {
            if (c <= 31 || c == 127) {
                throw new InvalidUrlException("URL contains invalid control characters or null bytes.");
            }
        }

        // Check scheme explicitly before URI parsing
        int colonIdx = trimmed.indexOf(':');
        if (colonIdx == -1) {
            // Auto-prepend https:// if the user provided only a domain (e.g., example.com)
            trimmed = "https://" + trimmed;
            colonIdx = trimmed.indexOf(':');
        }

        String scheme = trimmed.substring(0, colonIdx).toLowerCase(Locale.ROOT);
        if (!ALLOWED_SCHEMES.contains(scheme)) {
            throw new InvalidUrlException("Unsupported URL scheme: '" + scheme + "'. Only HTTP and HTTPS are permitted.");
        }

        try {
            URI uri = URI.create(trimmed);

            // Re-verify scheme from parsed URI
            if (uri.getScheme() == null || !ALLOWED_SCHEMES.contains(uri.getScheme().toLowerCase(Locale.ROOT))) {
                throw new InvalidUrlException("Unsupported or invalid URL scheme.");
            }

            // Verify host
            String host = uri.getHost();
            if (host == null || host.trim().isEmpty()) {
                throw new InvalidUrlException("URL does not contain a valid domain or host name.");
            }

            // Verify host does not contain spaces or illegal syntax
            if (host.contains(" ")) {
                throw new InvalidUrlException("Host name cannot contain spaces.");
            }

            // Reconstruct normalized URL (lowercased scheme and host, preserved path and query)
            String normalizedHost = host.toLowerCase(Locale.ROOT);
            StringBuilder normalized = new StringBuilder();
            normalized.append(uri.getScheme().toLowerCase(Locale.ROOT)).append("://").append(normalizedHost);

            if (uri.getPort() != -1) {
                normalized.append(":").append(uri.getPort());
            }

            String path = uri.getRawPath();
            if (path != null && !path.isEmpty()) {
                normalized.append(path);
            } else {
                normalized.append("/");
            }

            if (uri.getRawQuery() != null) {
                normalized.append("?").append(uri.getRawQuery());
            }

            return normalized.toString();

        } catch (IllegalArgumentException e) {
            throw new InvalidUrlException("Malformed URL syntax: " + e.getMessage());
        }
    }

    /**
     * Sanitizes sensitive credentials or tokens from query parameters before storage.
     */
    public String sanitizeForStorage(String url) {
        if (url == null) return "";
        return SENSITIVE_PARAM_PATTERN.matcher(url).replaceAll("$1=[REDACTED]");
    }

    /**
     * Completely strips query string and fragment to prevent sending sensitive tokens to external services.
     */
    public String stripQueryAndFragment(String url) {
        if (url == null || url.isBlank()) return "";
        try {
            URI uri = URI.create(url);
            String host = uri.getHost();
            if (host == null) return url;
            String scheme = uri.getScheme() != null ? uri.getScheme() : "https";
            StringBuilder sb = new StringBuilder(scheme).append("://").append(host.toLowerCase(Locale.ROOT));
            if (uri.getPort() != -1) {
                sb.append(":").append(uri.getPort());
            }
            String path = uri.getRawPath();
            if (path != null && !path.isEmpty()) {
                sb.append(path);
            } else {
                sb.append("/");
            }
            return sb.toString();
        } catch (Exception e) {
            int qIdx = url.indexOf('?');
            int hIdx = url.indexOf('#');
            int cutIdx = url.length();
            if (qIdx != -1) cutIdx = Math.min(cutIdx, qIdx);
            if (hIdx != -1) cutIdx = Math.min(cutIdx, hIdx);
            return url.substring(0, cutIdx);
        }
    }

    /**
     * Safely extracts the lowercased host from a URL.
     */
    public String extractHost(String url) {
        if (url == null || url.isBlank()) return "";
        try {
            URI uri = URI.create(url);
            String host = uri.getHost();
            return host != null ? host.toLowerCase(Locale.ROOT) : "";
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Safely extracts the sanitized path without query strings or fragments.
     */
    public String extractSanitizedPath(String url) {
        if (url == null || url.isBlank()) return "/";
        try {
            URI uri = URI.create(url);
            String path = uri.getRawPath();
            return (path != null && !path.isBlank()) ? path : "/";
        } catch (Exception e) {
            return "/";
        }
    }
}
