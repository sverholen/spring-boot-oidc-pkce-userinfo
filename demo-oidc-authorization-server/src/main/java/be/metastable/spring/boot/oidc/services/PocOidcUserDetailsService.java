package be.metastable.spring.boot.oidc.services;

import be.metastable.spring.boot.oidc.valueobjects.PocOidcUser;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Service
public class PocOidcUserDetailsService implements UserDetailsService {

    private static final Logger LOGGER = LoggerFactory.getLogger(PocOidcUserDetailsService.class);

    @Value("${test-oidc-authorization-server.test-user-username}")
    private String username;

    @Value("${test-oidc-authorization-server.test-user-password}")
    private String password;

    private final PasswordEncoder passwordEncoder;
    private final Map<String, PocOidcUser> users = new HashMap<>();

    public PocOidcUserDetailsService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @PostConstruct
    public void initUsers() {
        PocOidcUser testUser = new PocOidcUser(
                username,
                passwordEncoder.encode(password),
                "eDelta",
                "TestUser",
                "edelta.testuser@vlaanderen.be",
                Set.of("user", "admin"));

        users.put(username, testUser);

        LOGGER.info("Initialised users {}", testUser);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (users.containsKey(username)) {
            LOGGER.info("Found user for username '{}'", username);
            return users.get(username);
        }

        LOGGER.warn("No user found for username '{}'", username);
        throw new UsernameNotFoundException("No user found for username '" + username + "'");
    }
}
