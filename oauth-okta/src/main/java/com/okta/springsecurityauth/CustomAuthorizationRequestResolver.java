package com.okta.springsecurityauth;

import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class CustomAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    public static final String CODE_VERIFIER = "code_verifier";
    public static final String CODE_CHALLENGE = "code_challenge";
    public static final String CODE_CHALLENGE_METHOD = "code_challenge_method";

    private OAuth2AuthorizationRequestResolver defaultResolver;

    private final StringKeyGenerator secureKeyGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

    public CustomAuthorizationRequestResolver(ClientRegistrationRepository repo, String authorizationRequestBaseUri) {
        defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(repo, authorizationRequestBaseUri);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest servletRequest) {
//        OAuth2AuthorizationRequest req = defaultResolver.resolve(servletRequest);
//        return customizeAuthorizationRequest(req);
          String url = ((HttpServletRequest)servletRequest).getRequestURL().toString();
          String queryString = ((HttpServletRequest)servletRequest).getQueryString();
          return url.contains("/authorize/oauth2/") ?  null : this.resolve(servletRequest, "okta");
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest servletRequest, String clientRegistrationId) {
        OAuth2AuthorizationRequest req = defaultResolver.resolve(servletRequest, clientRegistrationId);
        return customizeAuthorizationRequest(req);
    }

    private OAuth2AuthorizationRequest customizeAuthorizationRequest(OAuth2AuthorizationRequest req) {

        if (req == null) { return null; }

        //Map<String, Object> attributes = new HashMap<>(req.getAttributes());
        Map<String, Object> additionalParameters = new HashMap<>(req.getAdditionalParameters());
        //addPkceParameters(attributes, additionalParameters);
        // String codeVerifier = this.secureKeyGenerator.generateKey();
        String codeVerifier = "abcde12345abcde12345abcde12345abcde12345abcde12345";
        //additionalParameters.put(CODE_VERIFIER, codeVerifier);
        try {
            String codeChallenge = createHash(codeVerifier);
            additionalParameters.put(CODE_CHALLENGE, codeChallenge);
            additionalParameters.put(CODE_CHALLENGE_METHOD, "S256");
            additionalParameters.put("scope", "openid profile email offline_access");
        } catch (NoSuchAlgorithmException e) {
            //additionalParameters.put(CODE_CHALLENGE, codeVerifier);
        }
        return OAuth2AuthorizationRequest.from(req)
                //.attributes(attributes)
                .additionalParameters(additionalParameters)
                .state("abcde12345")
                .build();
    }

    private static String createHash(String value) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(value.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}