package com.okta.springsecurityauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.web.client.RestTemplate;
import java.util.Arrays;
import static org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;

@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //String DEFAULT_AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/default/v1/authorize";

    private ClientRegistrationRepository clientRegistrationRepository;
    private Environment env;

    @Autowired
    CustomSuccessHandler successHandler;

    public SecurityConfig(ClientRegistrationRepository clientRegistrationRepository, Environment env) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.env = env;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
            .antMatchers("/", "/img/**", "/login/**", "/authorize/oauth2/**", "/callback/**", "/webjars/**", "/error**", "/logout")   // "/oauth2/**"
            .permitAll()
            .anyRequest()
            .fullyAuthenticated()
            .and()
            .oauth2Login()
            .authorizationEndpoint()
            .authorizationRequestResolver(new CustomAuthorizationRequestResolver(
                 clientRegistrationRepository, DEFAULT_AUTHORIZATION_REQUEST_BASE_URI
            ))
            .and()
            .successHandler(successHandler);
    }

//    @Bean
//    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient(){
//
//        DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
//        accessTokenResponseClient.setRequestEntityConverter(new CustomRequestEntityConverter());
//        OAuth2AccessTokenResponseHttpMessageConverter tokenResponseHttpMessageConverter = new OAuth2AccessTokenResponseHttpMessageConverter();
//        tokenResponseHttpMessageConverter.setTokenResponseConverter(new CustomTokenResponseConverter());
//        RestTemplate restTemplate = new RestTemplate(Arrays.asList(new FormHttpMessageConverter(), tokenResponseHttpMessageConverter));
//        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
//        accessTokenResponseClient.setRestOperations(restTemplate);
//        return accessTokenResponseClient;
//    }

//    @Bean
//    WebClient webClient(ClientRegistrationRepository clientRegistrations, OAuth2AuthorizedClientRepository authorizedClients) {
//
//        ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 =  new ServletOAuth2AuthorizedClientExchangeFilterFunction(clientRegistrations, authorizedClients);
//        oauth2.setDefaultOAuth2AuthorizedClient(true);
//        oauth2.setDefaultClientRegistrationId("okta");
//
//        return WebClient.builder()
//                .apply(oauth2.oauth2Configuration())
//                .build();
//    }

}