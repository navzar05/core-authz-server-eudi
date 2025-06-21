package ro.mta.baseauthzserver.model;

import org.springframework.security.core.userdetails.UserDetails;
import ro.mta.baseauthzserver.entity.BaseUser;

import java.util.Set;

/**
 * Extended UserDetails for EUDI authorization server
 */
public interface BaseUserDetails extends UserDetails {

    // Get the underlying user entity
    BaseUser getUser();
//
//    // EUDI specific methods
//    String getDidIdentifier();
//
//    Set<String> getVerifiableCredentials();
//
//    // Additional user information for consent screen
//    String getEmail();
//
//    String getDisplayName();
//
//    // Check if user has specific verifiable credential
//    boolean hasVerifiableCredential(String credentialType);
//
//    // Get user's consent preferences
//    Set<String> getConsentedScopes();
//
//    // Check if user has consented to specific scope
//    boolean hasConsentedToScope(String scope);
}