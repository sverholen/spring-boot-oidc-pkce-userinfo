package be.metastable.spring.boot.oidc.services;

import be.metastable.spring.boot.oidc.valueobjects.PocOidcUser;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;

@Service
public class PocOidcUserInfoService {

    private final PocOidcUserDetailsService userDetailsService;

    public PocOidcUserInfoService(PocOidcUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    public OidcUserInfo loadUser(String username) {
        PocOidcUser user = (PocOidcUser) userDetailsService.loadUserByUsername(username);

        return OidcUserInfo.builder()
                .subject(user.getUsername())
                .name(user.getFirstName() + " " + user.getLastName())
                .givenName(user.getFirstName())
                .familyName(user.getLastName())
                .nickname(username)
                .preferredUsername(username)
                .profile("https://edelta.vlaanderen.be/" + username)
                .website("https://edelta.vlaanderen.be")
                .email(user.getEmail())
                .emailVerified(true)
                .claim("roles", user.getRoles())
                .zoneinfo("Europe/Brussels")
                .locale("nl-BE")
                .updatedAt("1970-01-01T00:00:00Z")
                .build();
    }
}
