package com.louisfiges.auth.dto.mfa.request;

public record MfaVerifyRequest(
        String mfaToken,
        String code,
        String deviceFingerprint,  // Add this
        boolean trustDevice        // Add this
) {}