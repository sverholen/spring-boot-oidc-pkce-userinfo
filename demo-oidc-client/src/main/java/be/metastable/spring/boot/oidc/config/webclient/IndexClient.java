package be.metastable.spring.boot.oidc.config.webclient;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;

@HttpExchange("http://localhost:8090")
public interface IndexClient {

    @GetExchange("/")
    String getIndexMessage();
}
