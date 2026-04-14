package com.louisfiges.auth.token;

import com.louisfiges.common.KeyLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.Claims;

import java.security.Key;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

/**
 * TokenProvider is responsible for generating JWT tokens
 * using a signing key provided via configuration.
 * @author Louis Figes 
 */

public abstract class TokenProvider {
    private static final Logger logger = LoggerFactory.getLogger(TokenProvider.class);
    
    private final Key signingKey;
    
    public TokenProvider(String envVarName) {
        this.signingKey = KeyLoader.loadKeyFromEnv(envVarName);
    }

    protected String generate(UUID id, int expirationTime) {
        return Jwts.builder()
                .setSubject(String.valueOf(id))
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }

    protected String generate(UUID id, String username, int expirationTime) {
        return Jwts.builder()
                .setSubject(String.valueOf(id))
                .claim("username", username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public Optional<UUID> validateAndGetUserId(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            // Check expiration
            if (claims.getExpiration().before(new Date())) {
                logger.debug("Token expired");
                return Optional.empty();
            }

            return Optional.of(UUID.fromString(claims.getSubject()));
        } catch (JwtException e) {
            logger.error("Invalid token: {}", e.getMessage());
            return Optional.empty();
        }
    }
}