package ro.mta.baseauthzserver.config;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import ro.mta.baseauthzserver.authentication.pubclient.CustomPublicClientAuthenticationConverter;
import ro.mta.baseauthzserver.authentication.pubclient.CustomPublicClientAuthenticationProvider;
import ro.mta.baseauthzserver.authentication.preauthz.PreAuthorizedCodeGrantAuthenticationConverter;
import ro.mta.baseauthzserver.authentication.preauthz.PreAuthorizedCodeGrantAuthenticationProvider;
import ro.mta.baseauthzserver.service.PreAuthorizedCodeService;


import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.*;
import java.security.spec.ECGenParameterSpec;
import com.nimbusds.jose.jwk.ECKey;
import java.time.Duration;
import java.util.Arrays;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

    @Value("${spring.security.oauth2.authorizationserver.issuer}")
    public String ISSUER_URL;

    private static final String CUSTOM_CONSENT_PAGE_URI = "/oauth2/consent";

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/actuator/**", "/oauth2/**", "/.well-known/**", "/token/**"
                                , "/atm.JPG", "atm-logo.png", "/error").permitAll()
                        .requestMatchers("/h2-console/**").permitAll()
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/userinfo").authenticated()
                        .anyRequest().authenticated()
                )
                .exceptionHandling(exceptions -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                                new MediaTypeRequestMatcher(MediaType.APPLICATION_JSON)
                        )
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .permitAll()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(Customizer.withDefaults())
                )
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/h2-console/**", "/oauth2/**",
                                "/credential-offer/**", "/token/**", "/pre-authorize/**")
                );

        // Allow H2 console frames
        http.headers(
                headers -> headers.frameOptions(
                        frameOptions -> frameOptions.sameOrigin()));

        return http.build();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<?> tokenGenerator,
            @Autowired(required = false) RegisteredClientRepository registeredClientRepository, PreAuthorizedCodeService preAuthorizedCodeService) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);

        authorizationServerConfigurer
                .oidc(oidc -> oidc
                        .providerConfigurationEndpoint(provider -> provider
                                .providerConfigurationCustomizer(builder -> builder
                                        .grantTypes(grantTypes -> grantTypes.addAll(Arrays.asList(
                                                AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
                                                AuthorizationGrantType.CLIENT_CREDENTIALS.getValue(),
                                                "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                                        )))
                                )
                        )
                )
                .authorizationEndpoint(authorizationEndpoint ->
                        authorizationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI))
                .clientAuthentication(clientAuthentication ->
                        clientAuthentication
                                .authenticationConverter(new CustomPublicClientAuthenticationConverter())
                                .authenticationProvider(new CustomPublicClientAuthenticationProvider(
                                        registeredClientRepository))
                                .authenticationProviders(configurer -> {
                                })
                )

                .tokenEndpoint(tokenEndpoint ->
                        tokenEndpoint
                                .accessTokenRequestConverter(
                                        new PreAuthorizedCodeGrantAuthenticationConverter())
                                .authenticationProvider(
                                        new PreAuthorizedCodeGrantAuthenticationProvider(
                                                authorizationService, tokenGenerator, preAuthorizedCodeService))
                );

        http.exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(Customizer.withDefaults()));

        return http.build();
    }

//    @ConditionalOnMissingBean
//    public RegisteredClientRepository registeredClientRepository() {
//        // Client for the credential issuer service
//        RegisteredClient issuerClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("issuer-srv")
//                .clientSecret(passwordEncoder().encode("zIKAV9DIIIaJCzHCVBPlySgU8KgY68U2"))
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                .scope(OidcScopes.OPENID)
//                .scope(OidcScopes.PROFILE)
//                .scope("org.certsign.university_graduation_sdjwt")
//                .scope("issuer:credentials")
//                .build();
//
//        RegisteredClient eudiWalletClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("wallet-dev")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .authorizationGrantType(new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:pre-authorized_code"))
//                .redirectUri("eu.europa.ec.euidi://authorization")
//                .scope(OidcScopes.OPENID)
//                .scope(OidcScopes.PROFILE)
//                .scope("org.certsign.university_graduation_sdjwt")
//                .clientSettings(ClientSettings.builder()
//                        .requireAuthorizationConsent(true)
//                        .requireProofKey(true)
//                        .build())
//                .tokenSettings(TokenSettings.builder()
//                        .accessTokenTimeToLive(Duration.ofMinutes(1))
//                        .refreshTokenTimeToLive(Duration.ofMinutes(1))
//                        .reuseRefreshTokens(false)
//                        .build())
//                .build();
//
//        return new InMemoryRegisteredClientRepository(issuerClient, eudiWalletClient);
//    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(4096);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }


    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(ISSUER_URL)
                .authorizationEndpoint("/oauth2/authorize")
                .tokenEndpoint("/oauth2/token")
                .jwkSetEndpoint("/oauth2/jwks")
                .tokenRevocationEndpoint("/oauth2/revoke")
                .tokenIntrospectionEndpoint("/oauth2/introspect")
                .oidcUserInfoEndpoint("/userinfo")
                .build();
    }

    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    @Bean
    OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource) {
        JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }

    @Bean
    public AuthenticationManager authenticationManager(
            @Autowired(required = false) UserDetailsService userDetailsService,
            @Autowired(required = false) PasswordEncoder passwordEncoder) {


        DaoAuthenticationProvider daoAuthProvider = new DaoAuthenticationProvider();
        daoAuthProvider.setUserDetailsService(userDetailsService);
        daoAuthProvider.setPasswordEncoder(passwordEncoder);

        return new ProviderManager(daoAuthProvider);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService() {
        return new OAuth2AuthorizationConsentService() {
            @Override
            public void save(OAuth2AuthorizationConsent authorizationConsent) {
                // Don't save consent - this forces it to be requested every time
            }

            @Override
            public void remove(OAuth2AuthorizationConsent authorizationConsent) {
                // No-op
            }

            @Override
            public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
                // Always return null to force consent
                return null;
            }
        };
    }
}