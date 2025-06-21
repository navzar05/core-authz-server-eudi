package ro.mta.baseauthzserver.authentication.preauthz;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

import java.util.Collections;

/**
 * An {@link Authentication} implementation used for the Pre-Authorized Code Grant.
 *
 * This token represents a pre-authorized code grant where the authorization code
 * has been pre-authorized and can be exchanged directly for an access token
 * without requiring user interaction.
 */
@Getter
public class PreAuthorizedCodeGrantAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 1L;

    public static final AuthorizationGrantType PRE_AUTHORIZED_CODE_GRANT_TYPE =
            new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:pre-authorized_code");

    /**
     * -- GETTER --
     *  Returns the pre-authorized code.
     *
     * @return the pre-authorized code
     */
    private final String code;
    /**
     * -- GETTER --
     *  Returns the client principal.
     *
     * @return the client principal
     */
    private final Authentication clientPrincipal;

    private final String pin;


    /**
     * Constructs a {@code PreAuthorizedCodeGrantAuthenticationToken} using the provided parameters.
     *
     * @param code the pre-authorized code
     * @param clientPrincipal the authenticated client principal
     */
    public PreAuthorizedCodeGrantAuthenticationToken(String code, Authentication clientPrincipal) {
        this(code, clientPrincipal, null);
    }

    /**
     * Constructs a {@code PreAuthorizedCodeGrantAuthenticationToken} using the provided parameters.
     *
     * @param code the pre-authorized code
     * @param clientPrincipal the authenticated client principal
     */
    public PreAuthorizedCodeGrantAuthenticationToken(String code,
                                                     Authentication clientPrincipal,
                                                     String pin) {
        super(Collections.emptyList());
        Assert.hasText(code, "code cannot be empty");
        Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
        this.code = code;
        this.clientPrincipal = clientPrincipal;
        this.pin = pin;
    }

    /**
     * Returns the authorization grant type.
     *
     * @return the authorization grant type
     */
    public AuthorizationGrantType getGrantType() {
        return PRE_AUTHORIZED_CODE_GRANT_TYPE;
    }

    @Override
    public Object getCredentials() {
        return this.code;
    }

    @Override
    public Object getPrincipal() {
        return this.clientPrincipal;
    }

}