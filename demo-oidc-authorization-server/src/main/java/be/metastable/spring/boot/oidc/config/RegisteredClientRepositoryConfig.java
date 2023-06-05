package be.metastable.spring.boot.oidc.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Configuration
public class RegisteredClientRepositoryConfig {

    @Value("${test-oidc-authorization-server.client-port}")
    private int clientPort;

    @Value("${test-oidc-authorization-server.resource-server-port}")
    private int resourceServerPort;

    @Value("${test-oidc-authorization-server.default-client-registration}")
    private String defaultClientRegistration;

    @Value("${test-oidc-authorization-server.default-client-registration-id}")
    private String defaultClientRegistrationId;

    @Value("${test-oidc-authorization-server.default-client-registration-secret}")
    private String defaultClientRegistrationSecret;

    @Value("${test-oidc-authorization-server.with-pkce}")
    private boolean withPkce;

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        Set<String> redirectUris = new HashSet<>();
        redirectUris.add("http://127.0.0.1:" + resourceServerPort + "/login/oauth2/code/" + defaultClientRegistration);
        redirectUris.add("http://localhost:" + resourceServerPort + "/login/oauth2/code/" + defaultClientRegistration);

//        redirectUris.add("http://127.0.0.1:" + clientPort + "/client/callback");
//        redirectUris.add("http://127.0.0.1:" + clientPort + "/client");
        redirectUris.add("http://127.0.0.1:" + clientPort + "/login/oauth2/code/" + defaultClientRegistration);
//        redirectUris.add("http://localhost:" + clientPort + "/client/callback");
//        redirectUris.add("http://localhost:" + clientPort + "/client");
        redirectUris.add("http://localhost:" + clientPort + "/login/oauth2/code/" + defaultClientRegistration);
//        redirectUris.add("https://oauth.pstmn.io/v1/callback");

        Set<ClientAuthenticationMethod> clientAuthenticationMethods = new HashSet<>();
        clientAuthenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        clientAuthenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_POST);
        clientAuthenticationMethods.add(ClientAuthenticationMethod.NONE);

        Set<AuthorizationGrantType> authorizationGrantTypes = new HashSet<>();
        authorizationGrantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
        authorizationGrantTypes.add(AuthorizationGrantType.REFRESH_TOKEN);
        authorizationGrantTypes.add(AuthorizationGrantType.CLIENT_CREDENTIALS);

        Set<String> oidcScopes = new HashSet<>();
        oidcScopes.add(OidcScopes.OPENID);
        oidcScopes.add(OidcScopes.PROFILE);
        oidcScopes.add(OidcScopes.EMAIL);
        oidcScopes.add("read");
        oidcScopes.add("offline_access");

        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(defaultClientRegistrationId)
                .clientSecret(defaultClientRegistrationSecret)
                .clientAuthenticationMethods(methods -> methods.addAll(clientAuthenticationMethods))
                .authorizationGrantTypes(types -> types.addAll(authorizationGrantTypes))
                .redirectUris(uris -> uris.addAll(redirectUris))
                .scopes(scopes -> scopes.addAll(oidcScopes))
                .tokenSettings(tokenSettings())
                .clientSettings(clientSettings())
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    private TokenSettings tokenSettings() {
        return TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(15))
                .authorizationCodeTimeToLive(Duration.ofMinutes(2))
                .build();
    }

    private ClientSettings clientSettings() {
        return ClientSettings.builder()
                .requireProofKey(withPkce)
//                .requireAuthorizationConsent(false)
                .build();
    }
}
