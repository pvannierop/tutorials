package org.baeldung.security.filter;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;

import org.baeldung.security.oauth2.MyRestTemplate;
import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.map.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

@Component
public class OAuthTokenFilter extends GenericFilterBean {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Autowired
    MyRestTemplate refreshTokenRestTemplate;

    // @Autowired
    // AuthenticationManager authenticationManager;

    @Value("${google.jwkUrl}")
    private String jwkUrl;

    /**
     * Extract the bearer token from a header.
     */
    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {

        final String offlineToken = extractHeaderToken(request);

        if (offlineToken == null) {
            logger.error("Exception", "No token was found in request header");
            throw new BadCredentialsException("No offlineToken was passed");
        }

        final String accessToken = refreshTokenRestTemplate.getAccessToken(offlineToken);
        final String kid = JwtHelper.headers(accessToken).get("kid");

        Set<GrantedAuthority> authorities = null;
        String userName = null;
        try {
            final Jwt tokenDecoded = JwtHelper.decodeAndVerify(accessToken, verifier(kid));
            final String claims = tokenDecoded.getClaims();
            JsonNode claimsMap = new ObjectMapper().readTree(claims);
            userName = claimsMap.get("user_name").asText();
            Iterable<JsonNode> roles = () -> claimsMap.get("resource_access").get("cbioportal").get("roles")
                    .getElements();
            authorities = StreamSupport.stream(roles.spliterator(), false)
                    .map(role -> new SimpleGrantedAuthority(role.toString())).collect(Collectors.toSet());
        } catch (final MalformedURLException e) {
            logger.error("Exception", "Malformed URL for token endpoint (value encountered: '"+"')");
            throw e;
        } catch (final JwkException e) {
            logger.error("Exception", "Invalid JWT signature");
            throw new BadCredentialsException("Invalid JWT signature");
        } catch (final Exception e) {
            e.printStackTrace();
            throw e;
        }

        final Authentication authReq = new UsernamePasswordAuthenticationToken(userName, "", authorities);
        SecurityContextHolder.getContext().setAuthentication(authReq);

        chain.doFilter(request, response);
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
