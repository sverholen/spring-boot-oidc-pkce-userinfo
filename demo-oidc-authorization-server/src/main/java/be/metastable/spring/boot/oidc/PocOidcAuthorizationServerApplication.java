package be.metastable.spring.boot.oidc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class PocOidcAuthorizationServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(PocOidcAuthorizationServerApplication.class, args);
    }
}
