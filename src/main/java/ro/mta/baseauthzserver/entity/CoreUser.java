package ro.mta.baseauthzserver.entity;

import java.util.Set;

/**
 * Base interface that all CoreUser entities must implement
 */
public interface CoreUser {

    String getUsername();
    void setUsername(String username);

    String getPassword();
    void setPassword(String password);

    String getEmail();
    void setEmail(String email);

    String getVct();
    void setVct(String vct);

    boolean isEnabled();
    void setEnabled(boolean enabled);

    // Roles/Authorities
    Set<String> getRoles();
    void setRoles(Set<String> roles);
}