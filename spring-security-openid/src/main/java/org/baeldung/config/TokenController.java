package org.baeldung.config;

import org.baeldung.security.OpenIdConnectUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class TokenController {
    
    private final Logger logger = LoggerFactory.getLogger(getClass());

    @RequestMapping("/token")
    @ResponseBody
    public final String closed() {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        final OpenIdConnectUserDetails user = (OpenIdConnectUserDetails) authentication.getPrincipal();
        final OAuth2AccessToken accessToken = user.getToken();
        final String offlineToken = accessToken.getRefreshToken().toString();
        logger.info("Retrieved offline token for user: " + offlineToken);
        return "Token:\n" + offlineToken;
    }

}
