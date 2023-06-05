package be.metastable.spring.boot.oidc.config;

import be.metastable.spring.boot.oidc.services.PocOidcUserInfoService;
import be.metastable.spring.boot.oidc.utils.JwksUtils;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.stream.Collectors;

@Configuration
public class JwtConfig {

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(PocOidcUserInfoService userInfoService) {
        return context -> {
            if (!context.getAuthorizationGrantType().equals(AuthorizationGrantType.CLIENT_CREDENTIALS)) {
                if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue()) ||
                        OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                    OidcUserInfo userInfo = userInfoService.loadUser(context.getPrincipal().getName());

                    context.getClaims().claims(claims -> claims
                            .putAll(userInfo.getClaims()));
                    context.getClaims().claim("authorities", context.getPrincipal()
                            .getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet()));
                    context.getJwsHeader().type("jwt");
                }
            }
        };
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = JwksUtils.generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }
}
