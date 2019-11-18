package org.baeldung.config;

import javax.annotation.Resource;

import org.baeldung.security.filter.OAuth2TokenAccessFilter;
import org.baeldung.security.filter.OAuth2TokenRetrievalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Configuration
    @Order(100)
    public static class OAuth2TokenConfiguration extends WebSecurityConfigurerAdapter {

        @Resource
        private OAuth2RestTemplate restTemplate;

        @Bean
        public OAuth2TokenRetrievalFilter tokenRetrievalFilter() {
            final OAuth2TokenRetrievalFilter filter = new OAuth2TokenRetrievalFilter("/login");
            filter.setRestTemplate(restTemplate);
            return filter;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .antMatcher("/token")
                .addFilterAfter(new OAuth2ClientContextFilter(), AbstractPreAuthenticatedProcessingFilter.class)
                .addFilterAfter(tokenRetrievalFilter(), OAuth2ClientContextFilter.class)
                .httpBasic().authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                .and()
                .authorizeRequests()
                    .antMatchers("/token").authenticated();
                    // .antMatchers("/**").permitAll();
                    // .antMatchers(".closed").authenticated();
            ;
        }

    }

    @Configuration
    @Order(99)
    public static class ApiConfiguration extends WebSecurityConfigurerAdapter {

        // @Autowired
        // OAuth2TokenAccessFilter filter;

        @Bean
        public OAuth2TokenAccessFilter tokenAccessFilter() {
            final OAuth2TokenAccessFilter filter = new OAuth2TokenAccessFilter("/closed");
            return filter;
        }

        @Bean
        @Override
        public AuthenticationManager authenticationManagerBean() throws Exception {
            return super.authenticationManagerBean();
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // http.antMatcher("/closed").authorizeRequests() //
            //     .anyRequest().authenticated(); //
            //     // .and()
            //     // .addFilterBefore(filter, AbstractPreAuthenticatedProcessingFilter.class);
            http
                .antMatcher("/closed")
                .anonymous().disable()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilterAfter(tokenAccessFilter(), AbstractPreAuthenticatedProcessingFilter.class)
                .authorizeRequests()
                    // .anyRequest().hasAuthority("study_es_0");
                    .antMatchers("/closed").hasAuthority("study_es_0");
        }

    }
}
