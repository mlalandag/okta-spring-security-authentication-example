//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.okta.springsecurityauth;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.Builder;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;

public final class DefaultOAuth2AuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {
    private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final AntPathRequestMatcher authorizationRequestMatcher;
    private final StringKeyGenerator stateGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder());

    public DefaultOAuth2AuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository, String authorizationRequestBaseUri) {
        Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
        Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authorizationRequestMatcher = new AntPathRequestMatcher(authorizationRequestBaseUri + "/{" + "registrationId" + "}");
    }

    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        String registrationId = this.resolveRegistrationId(request);
        String redirectUriAction = this.getAction(request, "login");
        return this.resolve(request, registrationId, redirectUriAction);
    }

    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String registrationId) {
        if (registrationId == null) {
            return null;
        } else {
            String redirectUriAction = this.getAction(request, "authorize");
            return this.resolve(request, registrationId, redirectUriAction);
        }
    }

    private String getAction(HttpServletRequest request, String defaultAction) {
        String action = request.getParameter("action");
        return action == null ? defaultAction : action;
    }

    private OAuth2AuthorizationRequest resolve(HttpServletRequest request, String registrationId, String redirectUriAction) {
        if (registrationId == null) {
            return null;
        } else {
            ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
            if (clientRegistration == null) {
                throw new IllegalArgumentException("Invalid Client Registration with Id: " + registrationId);
            } else {
                Builder builder;
                if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(clientRegistration.getAuthorizationGrantType())) {
                    builder = OAuth2AuthorizationRequest.authorizationCode();
                } else {
                    if (!AuthorizationGrantType.IMPLICIT.equals(clientRegistration.getAuthorizationGrantType())) {
                        throw new IllegalArgumentException("Invalid Authorization Grant Type (" + clientRegistration.getAuthorizationGrantType().getValue() + ") for Client Registration with Id: " + clientRegistration.getRegistrationId());
                    }

                    builder = OAuth2AuthorizationRequest.implicit();
                }

                String redirectUriStr = this.expandRedirectUri(request, clientRegistration, redirectUriAction);
                Map<String, Object> additionalParameters = new HashMap();
                additionalParameters.put("registration_id", clientRegistration.getRegistrationId());
                OAuth2AuthorizationRequest authorizationRequest = builder.clientId(clientRegistration.getClientId()).authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri()).redirectUri(redirectUriStr).scopes(clientRegistration.getScopes()).state(this.stateGenerator.generateKey()).additionalParameters(additionalParameters).build();
                return authorizationRequest;
            }
        }
    }

    private String resolveRegistrationId(HttpServletRequest request) {
        return this.authorizationRequestMatcher.matches(request) ? (String)this.authorizationRequestMatcher.extractUriTemplateVariables(request).get("registrationId") : null;
    }

    private String expandRedirectUri(HttpServletRequest request, ClientRegistration clientRegistration, String action) {
        Map<String, String> uriVariables = new HashMap();
        uriVariables.put("registrationId", clientRegistration.getRegistrationId());
        String baseUrl = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request)).replaceQuery((String)null).replacePath(request.getContextPath()).build().toUriString();
        uriVariables.put("baseUrl", baseUrl);
        if (action != null) {
            uriVariables.put("action", action);
        }

        return UriComponentsBuilder.fromUriString(clientRegistration.getRedirectUriTemplate()).buildAndExpand(uriVariables).toUriString();
    }
}
