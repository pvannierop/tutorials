package org.baeldung.security.filter;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class OAuthTokenFilter extends AbstractAuthenticationProcessingFilter {

    // @Autowired
    // private DataAccessTokenServiceFactory dataAccessTokenServiceFactory;

    // private DataAccessTokenService tokenService;

    // @PostConstruct
    // public void postConstruct() {
    // if (datMethod == null || !SUPPORTED_DAT_METHODS.contains(datMethod)) {
    // this.tokenService = new UnauthDataAccessTokenServiceImpl();
    // } else {
    // this.tokenService =
    // this.dataAccessTokenServiceFactory.getDataAccessTokenService(this.datMethod);
    // }
    // }

    private final Logger logger = LoggerFactory.getLogger(getClass());

    public OAuthTokenFilter() {
        // allow any request to contain an authorization header
        super("/**");
    }

    @Override
    @Autowired
    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        super.setAuthenticationManager(authenticationManager);
    }

    @Override
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        // only required if we do see an authorization header
        String param = request.getHeader("Authorization");
        if (param == null) {
            logger.debug("attemptAuthentication(), authorization header is null, continue on to other security filters");
            return false;
        }
        return true;
    }

    @Override
    public Authentication attemptAuthentication (
        final HttpServletRequest request,
        final HttpServletResponse response) {

        String token = extractHeaderToken(request);

        if (token == null) {
            logger.error("No token was passed");
            throw new BadCredentialsException("No token was passed");
        }
        // TODO: here create call for retrieval of new access token
        // This call will use the offline token provided by the user in the request header.

        // TODO: validate the access token

        // TODO: retrieve the claims (authorities) from the access token

        // TODO: pass the claims to the Authentication object
        Set<GrantedAuthority> authorities = new HashSet<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        Authentication auth = new UsernamePasswordAuthenticationToken("offline user", authorities);
        return getAuthenticationManager().authenticate(auth);
    }

    @Override
    protected void successfulAuthentication(final HttpServletRequest request, final HttpServletResponse response, final FilterChain chain, final Authentication authResult) throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);
        chain.doFilter(request, response);
    }

    /**
     * Extract the bearer token from a header.
     */
    protected String extractHeaderToken(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        if (!StringUtils.isEmpty(authorizationHeader)) {
            if ((authorizationHeader.toLowerCase().startsWith("Bearer".toLowerCase()))) {
                return authorizationHeader.substring("Bearer".length()).trim();
            }
        }
        return null;
    }

    // @Override
    // public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
    //         throws IOException, ServletException {
    //     // TODO Auto-generated method stub
    //     super.doFilter(req, res, chain);
    // }

}
