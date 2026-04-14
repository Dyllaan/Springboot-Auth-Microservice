package com.louisfiges.auth.controller;

import com.louisfiges.auth.dto.mfa.request.LoginRequest;
import com.louisfiges.auth.dto.mfa.request.MfaVerifyRequest;
import com.louisfiges.auth.dto.request.AuthRequest;
import com.louisfiges.auth.dto.request.DeleteUserRequest;
import com.louisfiges.auth.dto.response.DeleteResult;
import com.louisfiges.auth.dto.response.LoginResult;
import com.louisfiges.auth.dto.request.RefreshRequest;
import com.louisfiges.auth.dto.request.UpdatePasswordRequest;
import com.louisfiges.auth.dto.response.UpdatePasswordResult;
import com.louisfiges.auth.dto.response.UserResponse;
import com.louisfiges.auth.service.UserService;
import com.louisfiges.auth.util.ValidPassword;
import com.louisfiges.auth.util.ValidUsername;
import com.louisfiges.common.dto.StringErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.louisfiges.auth.http.ResponseFactory;

import java.util.Map;

@RestController
@RequestMapping("/user")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        LoginResult result = userService.login(
                request.username(),
                request.password(),
                request.mfaCode(),
                request.deviceToken(),
                request.deviceFingerprint(),
                request.shouldTrustDevice()
        );

        return switch (result) {
            case LoginResult.Success success -> ResponseEntity.ok(success.response());
            case LoginResult.Failure failure -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new StringErrorResponse(failure.reason()));
            case LoginResult.MfaRequired mfaRequired -> ResponseEntity.status(HttpStatus.ACCEPTED)
                    .body(Map.of(
                            "mfaToken", mfaRequired.mfaToken(),
                            "message", mfaRequired.message()
                    ));
        };
    }

    @PostMapping("/verify-mfa")
    public ResponseEntity<?> verifyMfa(@RequestBody MfaVerifyRequest request) {
        LoginResult result = userService.verifyMfa(
                request.mfaToken(),
                request.code(),
                request.deviceFingerprint(),
                request.trustDevice()
        );

        return switch (result) {
            case LoginResult.Success success -> ResponseEntity.ok(success.response());
            case LoginResult.Failure failure -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new StringErrorResponse(failure.reason()));
            case LoginResult.MfaRequired ignore -> ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new StringErrorResponse("Unexpected state"));
        };
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshRequest request) {
        return userService.refreshToken(request.refreshToken())
                .<ResponseEntity<?>>map(loginResult ->
                        ResponseEntity.ok(((LoginResult.Success) loginResult).response())
                )
                .orElseGet(() -> ResponseEntity.status(401)
                        .body(ResponseFactory.error("Invalid refresh token")));
    }

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401)
                    .body(ResponseFactory.error("Missing or invalid authorization header"));
        }

        String token = authHeader.substring(7);

        return userService.getUserFromToken(token)
                .<ResponseEntity<?>>map(user ->
                        ResponseEntity.ok(new UserResponse(user.getUsername(), user.isMfaEnabled()))
                )
                .orElseGet(() -> ResponseEntity.status(401)
                        .body(ResponseFactory.error("Invalid token")));
    }

    @PostMapping("/update-password")
    public ResponseEntity<?> updatePassword(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody UpdatePasswordRequest request) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401)
                    .body(ResponseFactory.error("Missing or invalid authorization header"));
        }

        if (!ValidPassword.isValid(request.newPassword())) {
            return ResponseEntity.badRequest()
                    .body(ResponseFactory.error("Password does not meet complexity requirements"));
        }

        String token = authHeader.substring(7);

        return userService.updatePassword(token, request)
                .<ResponseEntity<?>>map(result -> switch (result) {
                    case UpdatePasswordResult.Success success ->
                            ResponseEntity.ok(Map.of("message", success.message()));
                    case UpdatePasswordResult.MfaRequired mfaRequired -> ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(new StringErrorResponse(mfaRequired.message()));
                    case UpdatePasswordResult.Failure failure -> ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(new StringErrorResponse(failure.message()));
                })
                .orElseGet(() -> ResponseEntity.status(401)
                        .body(ResponseFactory.error("Invalid token")));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody AuthRequest request) {
        if(!ValidPassword.isValid(request.password())) {
            return ResponseEntity.badRequest()
                    .body(ResponseFactory.error("Password does not meet complexity requirements"));
        }

        if(!ValidUsername.isValid(request.username())) {
            return ResponseEntity.badRequest()
                    .body(ResponseFactory.error("Username is invalid. It must be 3-48 characters long and can only contain letters, numbers, underscores, and hyphens."));
        }

        return userService.register(request.username(), request.password())
                .<ResponseEntity<?>>map(loginResult ->
                        ResponseEntity.status(HttpStatus.CREATED).body(((LoginResult.Success) loginResult).response())
                )
                .orElseGet(() -> ResponseEntity.status(409)
                        .body(ResponseFactory.error("Username already exists")));
    }

    // todo tell the workout service to delete user data as well
    @DeleteMapping("/delete")
    public ResponseEntity<?> deleteUser(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody(required = false) DeleteUserRequest request) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401)
                    .body(ResponseFactory.error("Missing or invalid authorization header"));
        }

        String token = authHeader.substring(7);
        String mfaCode = request != null ? request.mfaCode() : null;
        DeleteResult result = userService.deleteUser(token, mfaCode);

        return switch (result) {
            case DeleteResult.Success success ->
                    ResponseEntity.ok(Map.of("message", success.message()));
            case DeleteResult.MfaRequired mfaRequired ->
                    ResponseEntity.status(HttpStatus.BAD_REQUEST)
                            .body(new StringErrorResponse(mfaRequired.message()));
            case DeleteResult.Failure failure ->
                    ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(new StringErrorResponse(failure.reason()));
        };
    }
}