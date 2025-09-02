package com.authservice.authserviceoauth2.config;

import com.authservice.authserviceoauth2.service.CustomJdbcOAuth2AuthorizationService;
import com.authservice.authserviceoauth2.utility.PemUtils;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpSession;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcLogoutEndpointFilter;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

    private static final String STABLE_KEY_ID = UUID.randomUUID().toString();


    @Bean
    @Order(1)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // Create the Authorization Server configurer
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

        // Customize OIDC support
        authorizationServerConfigurer.oidc(Customizer.withDefaults());

        // Match only Authorization Server endpoints
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        // Apply Authorization Server security
        http
                .securityMatcher(endpointsMatcher)
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .cors(Customizer.withDefaults())
                .exceptionHandling(exceptions ->
                        exceptions.authenticationEntryPoint(
                                new LoginUrlAuthenticationEntryPoint("/login")
                        )
                )
                .with(authorizationServerConfigurer, configurer -> {
                    // No additional customizations here — but you could customize endpoints, etc.
                });

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    // Provide the issuer URL (important for OIDC discovery)
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:9053/auth2service")
                .build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsaKey();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static RSAKey generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(STABLE_KEY_ID)
                .build();
    }

    //for production
//    @Bean
//    public JWKSource<SecurityContext> jwkSource() throws Exception {
//        RSAKey rsaKey = loadRsaKey(); // Load from PEM files
//        JWKSet jwkSet = new JWKSet(rsaKey);
//        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
//    }
    // Load RSA key from PEM files in resources folder
//    private RSAKey loadRsaKey() throws Exception {
//        String publicKeyPEM = new String(new ClassPathResource("public.pem").getInputStream().readAllBytes(), StandardCharsets.UTF_8);
//        String privateKeyPEM = new String(new ClassPathResource("private.pem").getInputStream().readAllBytes(), StandardCharsets.UTF_8);
//
//        RSAPublicKey publicKey = PemUtils.parsePublicKey(publicKeyPEM);
//        RSAPrivateKey privateKey = PemUtils.parsePrivateKey(privateKeyPEM);
//
//        return new RSAKey.Builder(publicKey)
//                .privateKey(privateKey)
//                .keyID(STABLE_KEY_ID)
//                .build();
//    }


    @Bean
    public OAuth2AuthorizationService authorizationService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {

        return new CustomJdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(
            JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public CommandLineRunner registerClient(JdbcTemplate jdbcTemplate) {
        return args -> {
            RegisteredClientRepository repository = new JdbcRegisteredClientRepository(jdbcTemplate);

            if (repository.findByClientId("react-app-client-id") == null) {
                RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("react-app-client-id")
                        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .redirectUri("http://localhost:3000/callback")
                        .redirectUri("http://localhost:3000/silent-refresh.html")
                        .postLogoutRedirectUri("http://localhost:3000")
                        .scope(OidcScopes.OPENID)
                        .scope(OidcScopes.PROFILE)
                        .clientSettings(ClientSettings.builder()
                                .requireAuthorizationConsent(true)
                                .requireProofKey(true)
                                .build())
                        .tokenSettings(TokenSettings.builder()
                                .accessTokenTimeToLive(Duration.ofMinutes(15))
                                .refreshTokenTimeToLive(Duration.ofMinutes(30))
                                .reuseRefreshTokens(false)
                                .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                                .build())
                        .build();

                repository.save(registeredClient);
            }
        };
    }


}
