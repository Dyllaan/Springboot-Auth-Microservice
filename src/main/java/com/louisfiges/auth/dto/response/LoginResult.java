package com.louisfiges.auth.dto.response;

public sealed interface LoginResult permits LoginResult.Failure, LoginResult.MfaRequired, LoginResult.Success {
    record Success(AuthSuccessResponse response) implements LoginResult {}
    record Failure(String reason) implements LoginResult {}
    record MfaRequired(String mfaToken, String message) implements LoginResult {}
}