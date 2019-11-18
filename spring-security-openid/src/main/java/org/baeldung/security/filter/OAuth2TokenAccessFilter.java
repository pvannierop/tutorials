package org.baeldung.security.filter;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;

import org.baeldung.security.oauth2.TokenRefreshRestTemplate;
import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.map.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.StringUtils;

public class OAuth2TokenAccessFilter extends AbstractAuthenticationProcessingFilter {

    public OAuth2TokenAccessFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Value("${oidc.jwkUrl}")
    private String jwkUrl;

    @Autowired
    TokenRefreshRestTemplate tokenRefreshRestTemplate;

    @Override
    @Autowired
    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        super.setAuthenticationManager(authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {

        // get the offline token provided by the user (script)
        final String offlineToken = extractHeaderToken(request);

        if (offlineToken == null) {
            logger.error("Exception", "No token was found in request header");
            throw new BadCredentialsException("No offlineToken was passed");
        }

        // request an access token from the OAuth2 identity provider
        final String accessToken = tokenRefreshRestTemplate.getAccessToken(offlineToken);

        // extract the key-id for public key that signed the JWT
        final String kid = JwtHelper.headers(accessToken).get("kid");

        Set<GrantedAuthority> authorities = null;
        String userName = null;
        try {

            // validate token (using public key of the AOuth2 identity provider)
            final Jwt tokenDecoded = JwtHelper.decodeAndVerify(accessToken, verifier(kid));

            // get claims from token
            final String claims = tokenDecoded.getClaims();
            JsonNode claimsMap = new ObjectMapper().readTree(claims);
            userName = extractUserName(claimsMap);
            authorities = extractAuthorities(claimsMap);

        } catch (final MalformedURLException e) {
            logger.error("Exception", "Malformed URL for token endpoint (value encountered: '" + "')");
            throw e;
        } catch (final JwkException e) {
            logger.error("Exception", "Invalid JWT signature");
            throw new BadCredentialsException("Invalid JWT signature");
        } catch (final Exception e) {
            e.printStackTrace();
            throw e;
        }

        return new UsernamePasswordAuthenticationToken(userName, "", authorities);
    }

    private Set<GrantedAuthority> extractAuthorities(JsonNode claimsMap) {
        Set<GrantedAuthority> authorities;
        Iterable<JsonNode> roles = () -> claimsMap.get("resource_access").get("cbioportal").get("roles").getElements();
        authorities = StreamSupport.stream(roles.spliterator(), false).map(role -> role.toString().replaceAll("\"", ""))
                .map(role -> new SimpleGrantedAuthority(role)).collect(Collectors.toSet());
        return authorities;
    }

    private String extractUserName(JsonNode claimsMap) {
        String userName;
        userName = claimsMap.get("user_name").asText();
        return userName;
    }

    protected String extractHeaderToken(final ServletRequest request) {
        final String authorizationHeader = ((HttpServletRequest) request).getHeader("Authorization");
        if (!StringUtils.isEmpty(authorizationHeader)) {
            if ((authorizationHeader.toLowerCase().startsWith("Bearer".toLowerCase()))) {
                return authorizationHeader.substring("Bearer".length()).trim();
            }
        }
        return null;
    }

    private RsaVerifier verifier(final String kid) throws MalformedURLException, JwkException {
        final JwkProvider provider = new UrlJwkProvider(new URL(jwkUrl));
        final Jwk jwk = provider.get(kid);
        final RSAPublicKey publicKey = (RSAPublicKey) jwk.getPublicKey();
        return new RsaVerifier(publicKey, "SHA512withRSA");
    }

}
