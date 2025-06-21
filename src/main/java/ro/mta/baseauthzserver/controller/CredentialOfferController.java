package ro.mta.baseauthzserver.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ro.mta.baseauthzserver.entity.PreAuthorizedCode;
import ro.mta.baseauthzserver.service.PreAuthorizedCodeService;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/credential-offer")
@Slf4j
public class CredentialOfferController {

    private final PreAuthorizedCodeService preAuthorizedCodeService;
    private final ObjectMapper objectMapper;

    @Value("${openid4vci.issuer-url:https://192.168.1.137:8081/issuer-server}")
    private String credentialIssuer;

    public CredentialOfferController(PreAuthorizedCodeService preAuthorizedCodeService) {
        this.preAuthorizedCodeService = preAuthorizedCodeService;
        this.objectMapper = new ObjectMapper();
    }

    @PostMapping("/create")
    public ResponseEntity<Map<String, Object>> createCredentialOffer(@RequestBody Map<String, Object> request) {
        String clientId = (String) request.getOrDefault("client_id", "wallet-dev");
        String userId = (String) request.get("user_id");
        List<String> scopes = (List<String>) request.get("scopes");
        Boolean requirePin = (Boolean) request.getOrDefault("require_pin", true);

        // Create the pre-authorized code
        PreAuthorizedCode preAuth = preAuthorizedCodeService.createPreAuthorizedCode(
                clientId, userId, scopes, requirePin);

        // Build the OpenID4VCI compliant credential offer
        Map<String, Object> credentialOffer = createOpenID4VCICredentialOffer(preAuth);

        // Create the credential offer URL for QR code
        String credentialOfferUrl = createCredentialOfferUrl(credentialOffer);

        // Prepare the complete response
        Map<String, Object> response = new HashMap<>();
        response.put("credential_offer", credentialOffer);
        response.put("credential_offer_url", credentialOfferUrl);

        // Include the PIN separately for issuer display (not in QR code)
        if (preAuth.getPlainPin() != null) {
            response.put("user_pin", preAuth.getPlainPin());
            response.put("pin_display_message", "Display this PIN to the user: " + preAuth.getPlainPin());
        }

        long expiresIn = Duration.between(Instant.now(), preAuth.getExpiresAt()).getSeconds();
        response.put("expires_in", expiresIn);

        log.info("Created credential offer for user: {} with code: {}", userId, preAuth.getCode());
        return ResponseEntity.ok(response);
    }

    private Map<String, Object> createOpenID4VCICredentialOffer(PreAuthorizedCode preAuth) {
        Map<String, Object> offer = new HashMap<>();

        // Credential issuer (authorization server URL)
        offer.put("credential_issuer", credentialIssuer);

        // Use credential_configuration_ids (OpenID4VCI v13+ format)
        offer.put("credential_configuration_ids", new String[]{"org.certsign.university_graduation_sdjwt"});

        // Build grants section
        Map<String, Object> grants = new HashMap<>();
        Map<String, Object> preAuthGrant = new HashMap<>();

        // Pre-authorized code
        preAuthGrant.put("pre-authorized_code", preAuth.getCode());

        // Add tx_code specification if PIN is required (but not the actual PIN value)
        if (preAuth.getPin() != null) {
            Map<String, Object> txCode = new HashMap<>();
            txCode.put("length", 5);
            txCode.put("input_mode", "numeric");
            txCode.put("description", "Please provide the one-time code.");
            preAuthGrant.put("tx_code", txCode);
        }

        grants.put("urn:ietf:params:oauth:grant-type:pre-authorized_code", preAuthGrant);
        offer.put("grants", grants);

        return offer;
    }

    private String createCredentialOfferUrl(Map<String, Object> credentialOffer) {
        try {
            // Convert to JSON string
            String credentialOfferJson = objectMapper.writeValueAsString(credentialOffer);

            // URL encode the JSON
            String encodedOffer = URLEncoder.encode(credentialOfferJson, StandardCharsets.UTF_8);

            // Create the exact OpenID4VCI URL format
            return "openid-credential-offer://credential_offer?credential_offer=" + encodedOffer;

        } catch (JsonProcessingException e) {
            log.error("Failed to serialize credential offer", e);
            throw new RuntimeException("Failed to create credential offer URL", e);
        }
    }

}