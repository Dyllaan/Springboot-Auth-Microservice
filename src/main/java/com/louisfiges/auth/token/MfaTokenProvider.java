package com.louisfiges.auth.token;

import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * TokenProvider is responsible for generating JWT tokens
 * using a signing key provided via configuration.
 * @author Louis Figes
 */

@Component
public class MfaTokenProvider extends TokenProvider {
    // 5mins
    private static final int ACCESS_TOKEN_EXP_TIME = 1000 * 60 * 5;

    public MfaTokenProvider() {
        super("TEMP_MFA_SECRET_KEY");
    }

    public String generateToken(UUID id) {
        return generate(id, ACCESS_TOKEN_EXP_TIME);
    }

}