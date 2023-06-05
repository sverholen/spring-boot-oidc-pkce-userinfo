package be.metastable.spring.boot.oidc.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.function.Function;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class PocOidcAuthorizationServerConfig {


    private static final Logger LOGGER = LoggerFactory.getLogger(PocOidcAuthorizationServerConfig.class);

    @Value("${test-oidc-authorization-server.login-form-uri}")
    private String loginFormUri;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain asSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

//        OAuth2AuthorizationServerConfigurer configurer = new OAuth2AuthorizationServerConfigurer();
//        RequestMatcher endpointsMatcher = configurer.getEndpointsMatcher();
//
//        Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper = (context -> {
//            OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
//            JwtAuthenticationToken principal = (JwtAuthenticationToken) authentication.getPrincipal();
//
//            return new OidcUserInfo(principal.getToken().getClaims());
//        });
//
//        configurer.oidc(withDefaults()).oidc(oidc -> oidc
//                .userInfoEndpoint(userInfo -> userInfo.userInfoMapper(userInfoMapper)));
//
//        http
//                .securityMatcher(endpointsMatcher)
////                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
//                .exceptionHandling(e -> e
//                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint(loginFormUri)))
//                .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()))
//                .apply(configurer);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(withDefaults());

        return http
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint(loginFormUri)))
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()))
                .build();
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 1)
    public SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
//                .csrf(AbstractHttpConfigurer::disable)
//                .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
                .formLogin(withDefaults())
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
