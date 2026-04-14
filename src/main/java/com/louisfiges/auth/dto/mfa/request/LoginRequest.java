package com.louisfiges.auth.dto.mfa.request;

public record LoginRequest(
        String username,
        String password,
        String mfaCode,
        String deviceToken,
        String deviceFingerprint,
        Boolean trustDevice  // Nullable Boolean
) {
    // Provide defaults for null values
    public String mfaCode() {
        return mfaCode != null ? mfaCode : "";
    }

    public String deviceToken() {
        return deviceToken != null ? deviceToken : "";
    }

    public String deviceFingerprint() {
        return deviceFingerprint != null ? deviceFingerprint : "";
    }

    // Add a helper method with different name
    public boolean shouldTrustDevice() {
        return trustDevice != null && trustDevice;
    }
}