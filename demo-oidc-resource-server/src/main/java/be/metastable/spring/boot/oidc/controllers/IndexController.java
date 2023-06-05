package be.metastable.spring.boot.oidc.controllers;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;

@RestController
public class IndexController {

    @GetMapping("/")
    String api(@AuthenticationPrincipal Jwt jwt) {
        return String.format("You've made it: '%s'   ---    Token Claims: %s", fullName(jwt), jwt.getClaims());
    }

    private String fullName(Jwt jwt) {
        return String.format("%s %s", jwt.getClaimAsString("given_name"), jwt.getClaimAsString("family_name"));
    }
}
