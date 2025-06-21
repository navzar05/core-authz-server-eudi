package ro.mta.baseauthzserver.authentication.pubclient;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

import java.util.Map;

/**
 * Custom client authentication provider that handles public clients for pre-authorized code flows
 */
public class CustomPublicClientAuthenticationProvider implements AuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(CustomPublicClientAuthenticationProvider.class);

    private final RegisteredClientRepository registeredClientRepository;

    public CustomPublicClientAuthenticationProvider(RegisteredClientRepository registeredClientRepository) {
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2ClientAuthenticationToken clientAuthentication = (OAuth2ClientAuthenticationToken) authentication;

        if (!ClientAuthenticationMethod.NONE.equals(clientAuthentication.getClientAuthenticationMethod())) {
            return null;
        }

        String clientId = clientAuthentication.getPrincipal().toString();
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);

        if (registeredClient == null) {
            logger.error("Client not found: {}", clientId);
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }

        if (!registeredClient.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE)) {
            logger.error("Client {} does not support public authentication", clientId);
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }

        // Check if this is a pre-authorized code request
        Map<String, Object> additionalParameters = clientAuthentication.getAdditionalParameters();
        String grantType = (String) additionalParameters.get(OAuth2ParameterNames.GRANT_TYPE);

        if ("urn:ietf:params:oauth:grant-type:pre-authorized_code".equals(grantType)) {
            // For pre-authorized code, we don't need PKCE verification
            logger.debug("Authenticating public client for pre-authorized code grant: {}", clientId);
            return createSuccessfulAuthentication(clientAuthentication, registeredClient);
        } else {
            // For other flows (like authorization code), validate PKCE
            return validatePkceAndAuthenticate(clientAuthentication, registeredClient);
        }
    }

    private Authentication validatePkceAndAuthenticate(OAuth2ClientAuthenticationToken clientAuthentication,
                                                       RegisteredClient registeredClient) {
        Map<String, Object> additionalParameters = clientAuthentication.getAdditionalParameters();

        // For authorization code grant, require PKCE
        if (!additionalParameters.containsKey("code_verifier")) {
            logger.error("PKCE code_verifier is required for client: {}", registeredClient.getClientId());
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }

        logger.debug("Authenticating public client with PKCE: {}", registeredClient.getClientId());
        return createSuccessfulAuthentication(clientAuthentication, registeredClient);
    }

    private Authentication createSuccessfulAuthentication(OAuth2ClientAuthenticationToken clientAuthentication,
                                                          RegisteredClient registeredClient) {
        OAuth2ClientAuthenticationToken authenticationResult = new OAuth2ClientAuthenticationToken(
                registeredClient,
                clientAuthentication.getClientAuthenticationMethod(),
                clientAuthentication.getCredentials());
        authenticationResult.setDetails(clientAuthentication.getDetails());

        logger.info("Client authentication successful: {}", registeredClient.getClientId());
        return authenticationResult;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
    }
}