package org.baeldung.config;

import org.baeldung.security.oauth2.MyRestTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;

@Configuration
public class OAuth2TokenRefreshConfig {
    
    @Value("${google.clientId}")
    private String clientId;

    @Value("${google.clientSecret}")
    private String clientSecret;

    @Value("${google.accessTokenUri}")
    private String accessTokenUri;

    @Bean
    public OAuth2ProtectedResourceDetails tokenRefreshResourceDetails() {
        final AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
        details.setAccessTokenUri(accessTokenUri);
        details.setClientId(clientId);
        details.setClientSecret(clientSecret);
        return details;
    }

    @Bean
    public MyRestTemplate refreshTokenRestTemplate() {
        final MyRestTemplate template = new MyRestTemplate(tokenRefreshResourceDetails());
        return template;
    }

}
