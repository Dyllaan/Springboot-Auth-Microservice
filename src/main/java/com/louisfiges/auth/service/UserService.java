package com.louisfiges.auth.service;

import com.louisfiges.auth.dao.UserDAO;
import com.louisfiges.auth.dto.response.AuthSuccessResponse;
import com.louisfiges.auth.dto.response.DeleteResult;
import com.louisfiges.auth.dto.mfa.response.MfaSetupResponse;
import com.louisfiges.auth.dto.response.LoginResult;
import com.louisfiges.auth.dto.request.UpdatePasswordRequest;
import com.louisfiges.auth.dto.response.UpdatePasswordResult;
import com.louisfiges.auth.http.ResponseFactory;
import com.louisfiges.auth.http.exceptions.MfaValidationException;
import com.louisfiges.auth.repo.UserRepository;
import com.louisfiges.auth.token.MfaTokenProvider;
import com.louisfiges.auth.token.UserTokenProvider;
import dev.samstevens.totp.exceptions.QrGenerationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserTokenProvider userTokenProvider;
    private final MfaTokenProvider mfaTokenProvider;
    private final TotpService totpService;
    private final BackupCodeService backupCodeService;
    private final TrustedDeviceService trustedDeviceService;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, UserTokenProvider userTokenProvider, MfaTokenProvider mfaTokenProvider, TotpService totpService, BackupCodeService backupCodeService, TrustedDeviceService trustedDeviceService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.userTokenProvider = userTokenProvider;
        this.mfaTokenProvider = mfaTokenProvider;
        this.totpService = totpService;
        this.backupCodeService = backupCodeService;
        this.trustedDeviceService = trustedDeviceService;
    }

    public LoginResult login(String username, String password, String mfaCode,
                             String deviceToken, String deviceFingerprint, boolean trustDevice) {
        Optional<UserDAO> userOpt = userRepository.findByUsername(username);

        if (userOpt.isEmpty()) {
            return new LoginResult.Failure("Invalid credentials");
        }

        UserDAO user = userOpt.get();

        if (!passwordEncoder.matches(password, user.getPassword())) {
            return new LoginResult.Failure("Invalid credentials");
        }

        // Check if MFA is enabled
        if (user.isMfaEnabled()) {
            // Check if device is trusted
            if (deviceToken != null && deviceFingerprint != null) {
                boolean isTrusted = trustedDeviceService.isDeviceTrusted(deviceToken, deviceFingerprint);
                if (isTrusted) {
                    // Skip MFA for trusted device
                    return createSuccessResponse(user, null);
                }
            }

            // Device not trusted, require MFA
            if (mfaCode == null || mfaCode.isEmpty()) {
                String mfaToken = mfaTokenProvider.generateToken(user.getId());
                return new LoginResult.MfaRequired(mfaToken, "MFA code required");
            }

            // Verify MFA code
            boolean authenticated = totpService.verifyCode(user.getMfaSecret(), mfaCode);
            if (!authenticated) {
                authenticated = backupCodeService.verifyAndUseBackupCode(user, mfaCode);
            }

            if (!authenticated) {
                return new LoginResult.Failure("Invalid MFA code");
            }

            // MFA successful - create device token if requested
            String newDeviceToken = null;
            if (trustDevice && deviceFingerprint != null) {
                newDeviceToken = trustedDeviceService.createTrustedDevice(
                        user,
                        deviceFingerprint,
                        "Browser" // You can extract this from User-Agent
                );
            }

            return createSuccessResponse(user, newDeviceToken);
        }

        // No MFA enabled
        return createSuccessResponse(user, null);
    }

    private LoginResult.Success createSuccessResponse(UserDAO user, String deviceToken) {
        AuthSuccessResponse response = new AuthSuccessResponse(
                user.getUsername(),
                userTokenProvider.generateAccessToken(user.getId(), user.getUsername()),
                userTokenProvider.generateRefreshToken(user.getId(), user.getUsername()),
                user.isMfaEnabled(),
                deviceToken
        );
        return new LoginResult.Success(response);
    }

    @Transactional
    public LoginResult verifyMfa(String mfaToken, String code, String deviceFingerprint, boolean trustDevice) {
        return mfaTokenProvider.validateAndGetUserId(mfaToken)
                .flatMap(userRepository::findById)
                .map(user -> {
                    try {
                        // Verify MFA first
                        boolean authenticated = totpService.verifyCode(user.getMfaSecret(), code);
                        if (!authenticated) {
                            authenticated = backupCodeService.verifyAndUseBackupCode(user, code);
                        }

                        if (!authenticated) {
                            return new LoginResult.Failure("Invalid MFA code");
                        }

                        // MFA verified - create device token if requested
                        String newDeviceToken = null;
                        if (trustDevice && deviceFingerprint != null) {
                            newDeviceToken = trustedDeviceService.createTrustedDevice(
                                    user,
                                    deviceFingerprint,
                                    "Browser"
                            );
                        }

                        return ResponseFactory.loginResponse(
                                user.getUsername(),
                                userTokenProvider.generateAccessToken(user.getId(), user.getUsername()),
                                userTokenProvider.generateRefreshToken(user.getId(), user.getUsername()),
                                user.isMfaEnabled(),
                                newDeviceToken
                        );
                    } catch (Exception e) {
                        return new LoginResult.Failure(e.getMessage());
                    }
                })
                .orElse(new LoginResult.Failure("Invalid or expired MFA token"));
    }

    public Optional<LoginResult> register(String username, String password) {
        return userRepository.findByUsername(username)
                .isEmpty() ? Optional.of(userRepository.save(
                new UserDAO(
                        username,
                        passwordEncoder.encode(password),
                        LocalDateTime.now(),
                        false
                )
        )).map(user -> ResponseFactory.loginResponse(
                user.getUsername(),
                userTokenProvider.generateAccessToken(user.getId(), user.getUsername()),
                userTokenProvider.generateRefreshToken(user.getId(), user.getUsername()),
                user.isMfaEnabled(),
                null
        )) : Optional.empty();
    }

    public Optional<LoginResult> refreshToken(String refreshToken) {
        return userTokenProvider.validateAndGetUserId(refreshToken)
                .flatMap(userRepository::findById)
                .map(user -> ResponseFactory.loginResponse(
                        user.getUsername(),
                        userTokenProvider.generateAccessToken(user.getId(), user.getUsername()),
                        userTokenProvider.generateRefreshToken(user.getId(), user.getUsername()),
                        user.isMfaEnabled(),
                        null
                ));
    }

    @Transactional
    public Optional<UpdatePasswordResult> updatePassword(String token, UpdatePasswordRequest request) {
        Optional<UserDAO> userOpt = userTokenProvider.validateAndGetUserId(token)
                .flatMap(userRepository::findById);

        if (userOpt.isEmpty()) {
            return Optional.of(new UpdatePasswordResult.Failure("Invalid token"));
        }

        UserDAO user = userOpt.get();
        String mfaCode = request.mfaCode();

        if (user.isMfaEnabled()) {
            if (mfaCode == null || mfaCode.isEmpty()) {
                return Optional.of(new UpdatePasswordResult.MfaRequired("MFA code required for password update"));
            }

            boolean authenticated = totpService.verifyCode(user.getMfaSecret(), mfaCode);
            if (!authenticated) {
                authenticated = backupCodeService.verifyAndUseBackupCode(user, mfaCode);
            }

            if (!authenticated) {
                return Optional.of(new UpdatePasswordResult.Failure("Invalid MFA code"));
            }
        }

        if (!passwordEncoder.matches(request.oldPassword(), user.getPassword())) {
            return Optional.of(new UpdatePasswordResult.Failure("Old password is incorrect"));
        }

        user.setPassword(passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);
        return Optional.of(new UpdatePasswordResult.Success("Password updated successfully"));
    }

    public Optional<UserDAO> getUserFromToken(String token) {
        return userTokenProvider.validateAndGetUserId(token)
                .flatMap(userRepository::findById);
    }

    @Transactional
    public Optional<String> verifyAndEnableMfa(String token, String code) {
        return userTokenProvider.validateAndGetUserId(token)
                .flatMap(userRepository::findById)
                .filter(user -> user.getMfaSecret() != null)
                .filter(user -> totpService.verifyCode(user.getMfaSecret(), code))
                .map(user -> {
                    user.setMfaEnabled(true);
                    userRepository.save(user);
                    return "MFA enabled successfully";
                });
    }

    @Transactional
    public Optional<String> disableMfa(String token, String code) {
        return userTokenProvider.validateAndGetUserId(token)
                .flatMap(userRepository::findById)
                .filter(UserDAO::isMfaEnabled)
                .filter(user -> totpService.verifyCode(user.getMfaSecret(), code))
                .map(user -> {
                    user.setMfaEnabled(false);
                    user.setMfaSecret(null);
                    backupCodeService.deleteBackupCodes(user);
                    userRepository.save(user);
                    return "MFA disabled successfully";
                });
    }

    @Transactional
    public Optional<MfaSetupResponse> setupMfa(String token) {
        return userTokenProvider.validateAndGetUserId(token)
                .flatMap(userRepository::findById)
                .flatMap(user -> {
                    if(user.isMfaEnabled()) {
                        return Optional.empty();
                    }

                    String secret;
                    List<String> backupCodes;

                    if (user.getMfaSecret() != null && !user.getMfaSecret().isEmpty()) {
                        // Use existing secret
                        secret = user.getMfaSecret();
                        // Return existing backup codes (or regenerate if needed)
                        backupCodes = List.of(); // You might want to fetch existing codes
                    } else {
                        // Generate new secret only if none exists
                        secret = totpService.generateSecret();
                        user.setMfaSecret(secret);
                        userRepository.save(user);
                        backupCodes = backupCodeService.generateAndSaveBackupCodes(user, 10);
                    }

                    try {
                        String qrCode = totpService.generateQrCodeDataUri(secret, user.getUsername());
                        return Optional.of(new MfaSetupResponse(
                                secret,
                                qrCode,
                                backupCodes,
                                "Scan the QR code with your authenticator app and save your backup codes"
                        ));
                    } catch (QrGenerationException e) {
                        return Optional.empty();
                    }
                });
    }


    private String createDeviceToken(String code, UserDAO user, boolean trustDevice, String deviceFingerprint) throws MfaValidationException {
        boolean authenticated = totpService.verifyCode(user.getMfaSecret(), code);

        // If TOTP fails, try backup code
        if (!authenticated) {
            authenticated = backupCodeService.verifyAndUseBackupCode(user, code);
        }

        if (!authenticated) {
            throw new MfaValidationException("Invalid MFA code");
        }

        // MFA successful - create device token if requested
        String newDeviceToken = null;
        if (trustDevice && deviceFingerprint != null) {
            newDeviceToken = trustedDeviceService.createTrustedDevice(
                    user,
                    deviceFingerprint,
                    "Browser"
            );
        }
        return newDeviceToken != null ? newDeviceToken : "";
    }

    @Transactional
    public DeleteResult deleteUser(String token, String mfaCode) {
        Optional<UserDAO> userOpt = userTokenProvider.validateAndGetUserId(token)
                .flatMap(userRepository::findById);

        if (userOpt.isEmpty()) {
            return new DeleteResult.Failure("Invalid token");
        }

        UserDAO user = userOpt.get();

        if (user.isMfaEnabled()) {
            if (mfaCode == null || mfaCode.isEmpty()) {
                return new DeleteResult.MfaRequired("MFA code required for account deletion");
            }

            boolean authenticated = totpService.verifyCode(user.getMfaSecret(), mfaCode);
            if (!authenticated) {
                authenticated = backupCodeService.verifyAndUseBackupCode(user, mfaCode);
            }

            if (!authenticated) {
                return new DeleteResult.Failure("Invalid MFA code");
            }
        }

        userRepository.delete(user);
        return new DeleteResult.Success("User deleted successfully");
    }
}