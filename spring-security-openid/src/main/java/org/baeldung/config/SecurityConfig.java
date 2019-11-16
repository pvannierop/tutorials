package org.baeldung.config;

import javax.annotation.Resource;

import org.baeldung.security.entrypoint.RestAuthenticationEntryPoint;
import org.baeldung.security.filter.OAuthTokenFilter;
import org.baeldung.security.filter.OpenIdConnectFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

@EnableWebSecurity
public class SecurityConfig {

    @Configuration
    @Order(100)
    public static class OAuth2TokenConfiguration extends WebSecurityConfigurerAdapter {

        @Resource
        private OAuth2RestTemplate restTemplate;

        @Bean
        public OpenIdConnectFilter myFilter() {
            final OpenIdConnectFilter filter = new OpenIdConnectFilter("/login");
            filter.setRestTemplate(restTemplate);
            return filter;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .addFilterAfter(new OAuth2ClientContextFilter(), AbstractPreAuthenticatedProcessingFilter.class)
                .addFilterAfter(myFilter(), OAuth2ClientContextFilter.class)
                .httpBasic()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                .and()
                .authorizeRequests()
                    .antMatchers("/token").authenticated()
                .and()
                .authorizeRequests()
                    .antMatchers("/**").permitAll();
        }

    }

    @Configuration
    @Order(99)
    public static class ApiConfiguration extends WebSecurityConfigurerAdapter {

        @Autowired
        RestAuthenticationEntryPoint restAuthenticationEntryPoint;

        @Autowired
        OAuthTokenFilter filter;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.antMatcher("/closed")
                    .anonymous().disable()
                    .csrf().disable()
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                    .addFilterAfter(filter, AbstractPreAuthenticatedProcessingFilter.class)
                    .authorizeRequests()
                        .antMatchers("/closed").authenticated();
        }

    }
}
