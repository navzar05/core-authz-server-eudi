package ro.mta.baseauthzserver.service;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import ro.mta.baseauthzserver.model.BaseUserDetails;

/**
 * Extended UserDetailsService for EUDI authorization server
 */
public interface BaseUserDetailsService extends UserDetailsService {

    @Override
    BaseUserDetails loadUserByUsername(String username) throws UsernameNotFoundException;

//    // Additional methods for EUDI functionality
//    BaseUserDetails loadUserByEmail(String email) throws UsernameNotFoundException;
//
//    BaseUserDetails loadUserByDidIdentifier(String didIdentifier) throws UsernameNotFoundException;
//
//    // Update user consent
//    void updateUserConsent(String username, String clientId, String scope);
//
//    // Check if user has given consent for specific client and scope
//    boolean hasUserConsentedToScope(String username, String clientId, String scope);
}
