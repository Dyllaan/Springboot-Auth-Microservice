package com.louisfiges.auth.token;

import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * TokenProvider is responsible for generating JWT tokens
 * using a signing key provided via configuration.
 * @author Louis Figes
 */

@Component
public class UserTokenProvider extends TokenProvider {
    private static final int ACCESS_TOKEN_EXP_TIME = 1000 * 60 * 15; // 15 minutes
    private static final long REFRESH_TOKEN_EXP_TIME = 1000L * 60 * 60 * 24 * 28; // 28 days

    public UserTokenProvider() {
        super("SECRET_KEY");
    }

    public String generateAccessToken(UUID id, String username) {
        return generate(id, username, ACCESS_TOKEN_EXP_TIME);
    }

    public String generateRefreshToken(UUID id, String username) {
        return generate(id, username, REFRESH_TOKEN_EXP_TIME);
    }
}