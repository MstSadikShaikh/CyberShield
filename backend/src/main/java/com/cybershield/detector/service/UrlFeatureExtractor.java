package com.cybershield.detector.service;

import com.cybershield.detector.dto.UrlIndicatorDto;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.*;
import java.util.regex.Pattern;

@Service
public class UrlFeatureExtractor {

    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^(\\d{1,3}\\.){3}\\d{1,3}$"
    );

    private static final Set<String> SUSPICIOUS_TLDS = Set.of(
            ".xyz", ".top", ".club", ".work", ".click", ".link", ".buzz",
            ".fit", ".gq", ".tk", ".ml", ".ga", ".cf", ".cam", ".rest"
    );

    private static final List<String> PHISHING_KEYWORDS = List.of(
            "login", "signin", "verify", "verification", "account-update", "banking",
            "security-check", "authenticate", "webscr", "ebayisapi", "recover",
            "wallet", "metamask", "paypal", "appleid", "microsoft-login"
    );

    public List<UrlIndicatorDto> extractIndicators(String url) {
        List<UrlIndicatorDto> indicators = new ArrayList<>();

        try {
            URI uri = URI.create(url);
            String host = uri.getHost() != null ? uri.getHost().toLowerCase(Locale.ROOT) : "";
            String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase(Locale.ROOT) : "";
            String path = uri.getPath() != null ? uri.getPath().toLowerCase(Locale.ROOT) : "";
            String fullLower = url.toLowerCase(Locale.ROOT);

            // 1. Protocol / HTTPS
            if ("https".equalsIgnoreCase(scheme)) {
                indicators.add(new UrlIndicatorDto(
                        "Transport Encryption",
                        "HTTPS (TLS)",
                        "SAFE",
                        "Connection is encrypted in transit. (Note: over 80% of phishing sites also use HTTPS; encryption does not prove legitimacy)."
                ));
            } else {
                indicators.add(new UrlIndicatorDto(
                        "Transport Encryption",
                        "HTTP (Plaintext)",
                        "WARNING",
                        "Unencrypted connection. Legitimate login or banking services never use plaintext HTTP."
                ));
            }

            // 2. IP Address in Host
            boolean isIp = IPV4_PATTERN.matcher(host).matches();
            if (isIp) {
                indicators.add(new UrlIndicatorDto(
                        "Host Type",
                        "Raw IP Address (" + host + ")",
                        "DANGER",
                        "Using a raw IP address instead of a domain name is a classic evasion and phishing indicator."
                ));
            } else {
                indicators.add(new UrlIndicatorDto(
                        "Host Type",
                        "Domain Name (" + host + ")",
                        "SAFE",
                        "Host uses a registered domain name."
                ));
            }

            // 3. Userinfo '@' symbol spoofing
            if (url.contains("@")) {
                indicators.add(new UrlIndicatorDto(
                        "URL Obfuscation",
                        "Embedded '@' character",
                        "DANGER",
                        "Browser will treat everything before '@' as user credentials and navigate only to the destination host after '@'."
                ));
            }

            // 4. Subdomain nesting count
            String[] hostParts = host.split("\\.");
            int subdomainCount = Math.max(0, hostParts.length - 2);
            if (subdomainCount >= 3) {
                indicators.add(new UrlIndicatorDto(
                        "Subdomain Depth",
                        subdomainCount + " subdomains",
                        "WARNING",
                        "High subdomain nesting (" + host + ") is commonly used to impersonate well-known brand names."
                ));
            } else {
                indicators.add(new UrlIndicatorDto(
                        "Subdomain Depth",
                        subdomainCount + " subdomain(s)",
                        "SAFE",
                        "Standard domain depth."
                ));
            }

            // 5. Hyphens in domain
            long hyphenCount = host.chars().filter(ch -> ch == '-').count();
            if (hyphenCount >= 2) {
                indicators.add(new UrlIndicatorDto(
                        "Hyphens in Hostname",
                        hyphenCount + " hyphens",
                        "WARNING",
                        "Multiple hyphens in domain names are frequently used in brand spoofing (e.g., 'paypal-security-update')."
                ));
            }

            // 6. Suspicious TLD check
            boolean hasSuspiciousTld = false;
            for (String tld : SUSPICIOUS_TLDS) {
                if (host.endsWith(tld)) {
                    hasSuspiciousTld = true;
                    indicators.add(new UrlIndicatorDto(
                            "Top-Level Domain (TLD)",
                            tld,
                            "WARNING",
                            "This TLD has a statistically high correlation with disposable, low-cost phishing campaigns."
                    ));
                    break;
                }
            }
            if (!hasSuspiciousTld && hostParts.length >= 2) {
                indicators.add(new UrlIndicatorDto(
                        "Top-Level Domain",
                        "." + hostParts[hostParts.length - 1],
                        "INFO",
                        "Standard registered top-level domain."
                ));
            }

            // 7. Suspicious Keywords
            List<String> matchedKeywords = new ArrayList<>();
            for (String kw : PHISHING_KEYWORDS) {
                if (fullLower.contains(kw)) {
                    matchedKeywords.add(kw);
                }
            }
            if (!matchedKeywords.isEmpty()) {
                indicators.add(new UrlIndicatorDto(
                        "Sensitive Keywords",
                        String.join(", ", matchedKeywords),
                        "WARNING",
                        "Contains authentication or security-sensitive keywords often targeted by phishing kits."
                ));
            }

            // 8. Shannon Entropy of Host (Randomness / DGA detection)
            double hostEntropy = calculateShannonEntropy(host);
            if (hostEntropy > 3.8 && host.length() > 15) {
                indicators.add(new UrlIndicatorDto(
                        "Hostname Entropy",
                        String.format("%.2f bits/char", hostEntropy),
                        "WARNING",
                        "High character entropy indicates potentially algorithmically generated (DGA) domain."
                ));
            } else {
                indicators.add(new UrlIndicatorDto(
                        "Hostname Entropy",
                        String.format("%.2f bits/char", hostEntropy),
                        "SAFE",
                        "Normal linguistic character distribution."
                ));
            }

            // 9. Length indicator
            if (url.length() > 75) {
                indicators.add(new UrlIndicatorDto(
                        "URL Length",
                        url.length() + " characters",
                        "WARNING",
                        "Unusually long URL. Attackers frequently use long URLs to hide malicious domain targets on mobile screens."
                ));
            } else {
                indicators.add(new UrlIndicatorDto(
                        "URL Length",
                        url.length() + " characters",
                        "SAFE",
                        "Standard URL length."
                ));
            }

        } catch (Exception e) {
            indicators.add(new UrlIndicatorDto("Analysis Error", "Failed to parse features", "INFO", e.getMessage()));
        }

        return indicators;
    }

    /**
     * Calculates Shannon entropy (H = -sum(p * log2(p))) for character sequence.
     */
    public double calculateShannonEntropy(String input) {
        if (input == null || input.isEmpty()) return 0.0;
        Map<Character, Integer> freqMap = new HashMap<>();
        for (char c : input.toCharArray()) {
            freqMap.put(c, freqMap.getOrDefault(c, 0) + 1);
        }
        double entropy = 0.0;
        int len = input.length();
        for (int count : freqMap.values()) {
            double prob = (double) count / len;
            entropy -= prob * (Math.log(prob) / Math.log(2));
        }
        return entropy;
    }
}
