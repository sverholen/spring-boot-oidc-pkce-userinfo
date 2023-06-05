package be.metastable.spring.boot.oidc.controllers;

import be.metastable.spring.boot.oidc.config.webclient.IndexClient;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexController {

    private final IndexClient indexClient;

    public IndexController(IndexClient indexClient) {
        this.indexClient = indexClient;
    }

    @GetMapping("/")
    public String index(@AuthenticationPrincipal OidcUser oidcUser, Model model) {
        model.addAttribute("name", oidcUser.getIdToken().getFullName());
        model.addAttribute("token_claims", oidcUser.getIdToken().getClaims());
        model.addAttribute("userinfo_claims", oidcUser.getUserInfo().getClaims());

        return "index";
    }

    @GetMapping("/demo")
    String demo(@AuthenticationPrincipal OidcUser oidcUser, Model model) {
        model.addAttribute("name", oidcUser.getIdToken().getFullName());
        String message = indexClient.getIndexMessage();
        model.addAttribute("message", message);

        return "demo";
    }
}
