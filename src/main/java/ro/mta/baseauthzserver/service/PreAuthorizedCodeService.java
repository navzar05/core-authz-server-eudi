// 2. Service for managing pre-authorized codes
package ro.mta.baseauthzserver.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ro.mta.baseauthzserver.entity.PreAuthorizedCode;
import ro.mta.baseauthzserver.repository.PreAuthorizedCodeRepository;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class PreAuthorizedCodeService {

    private final PreAuthorizedCodeRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${eudi.preauth.code.expiry.minutes:10}")
    private int codeExpiryMinutes;

    @Transactional
    public PreAuthorizedCode createPreAuthorizedCode(String clientId, String userId,
                                                     List<String> scopes,
                                                     boolean requirePin) {
        String code = generateSecureCode(32);
        String pin = null;
        String plainPin = null;

        if (requirePin) {
            //TODO: HARDCODAM PUTIN...
            plainPin = generatePin();
            plainPin = String.valueOf(12345);
            pin = passwordEncoder.encode(plainPin);
        }

        PreAuthorizedCode preAuthCode = PreAuthorizedCode.builder()
                .code(code)
                .clientId(clientId)
                .userId(userId)
                .scopes(scopes)
                .pin(pin)
                .plainPin(plainPin)
                .used(false)
                .expiresAt(Instant.now().plus(codeExpiryMinutes, ChronoUnit.MINUTES))
                .createdAt(Instant.now())
                .build();

        return repository.save(preAuthCode);
    }

    @Transactional
    public Optional<PreAuthorizedCode> validateAndConsume(String code, String pin) {
        Optional<PreAuthorizedCode> preAuthOpt = repository
                .findByCodeAndUsedFalseAndExpiresAtAfter(code, Instant.now());

        if (preAuthOpt.isEmpty()) {
            return Optional.empty();
        }

        PreAuthorizedCode preAuth = preAuthOpt.get();

        if (preAuth.getPin() != null) {
            if (pin == null || !passwordEncoder.matches(pin, preAuth.getPin())) {
                return Optional.empty();
            }
        }

        preAuth.setUsed(true);
        repository.save(preAuth);
        return Optional.of(preAuth);
    }

    private String generateSecureCode(int length) {
        StringBuilder code = new StringBuilder();
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        for (int i = 0; i < length; i++) {
            code.append(chars.charAt(secureRandom.nextInt(chars.length())));
        }
        return code.toString();
    }

    private String generatePin() {
        return String.format("%05d", secureRandom.nextInt(100000));
    }
}