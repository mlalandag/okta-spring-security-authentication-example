package com.okta.springsecurityauth;

import net.minidev.json.JSONObject;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.awt.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Controller
public class WebController {

    @RequestMapping("/")
    @ResponseBody
    public String home(@AuthenticationPrincipal OidcUser oidcUser) {
        return "Welcome, " + oidcUser.getFullName();
    }

    @RequestMapping("/attributes")
    @ResponseBody
    public String attributes(@AuthenticationPrincipal OidcUser oidcUser) {
        return oidcUser.getAttributes().toString();
    }

    @RequestMapping("/authorities")
    @ResponseBody
    public String authorities(@AuthenticationPrincipal OidcUser oidcUser) {
        return oidcUser.getAuthorities().toString();
    }

    @RequestMapping("/authorize/oauth2/code/okta")
    @ResponseBody
    public String autorizationCode(@RequestParam String code, @RequestParam String state) {
        System.out.println("Authorization Code = " + code + ", Status = " + state);
//    public String autorizationCode(@RequestParam String state) {
//        System.out.println("Status = " + state);

        // Verificar state para comprobar que no se ha lterado la petición.

        String url = "https://dev-81525397.okta.com/oauth2/default/v1/token";
        String codeVerifier = "abcde12345abcde12345abcde12345abcde12345abcde12345";

        RestTemplateBuilder restTemplateBuilder = new RestTemplateBuilder();
        RestTemplate restTemplate = restTemplateBuilder.errorHandler(new RestTemplateResponseErrorHandler()).build();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        //headers.add("Accept", "application/json");
        headers.add("Accept", MediaType.APPLICATION_JSON.toString());
        //headers.add("cache-control", "no-cache");

        MultiValueMap<String, String> map = new LinkedMultiValueMap<String, String>();
        map.add("grant_type","authorization_code");
        map.add("client_id","0oa10j8ylpONE5G995d7");
        map.add("redirect_uri","http://localhost:8080/authorize/oauth2/code/okta");
        map.add("code_verifier",codeVerifier);
        map.add("code", code);
//        try {
//            String codeChallenge = createHash(codeVerifier);
//            map.add("code_challenge", codeChallenge);
//            map.add("code_challenge_method", "S256");
//        } catch (NoSuchAlgorithmException e) {
//            //additionalParameters.put(CODE_CHALLENGE, codeVerifier);
//        }

        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<MultiValueMap<String, String>>(map , headers);

//        ResponseEntity<String> response = restTemplate.postForEntity(url, entity, String.class);

        ResponseEntity<String> responseEntity  = restTemplate.exchange(url, HttpMethod.POST, entity, String.class);

        System.out.println("Acces token response >>> " + responseEntity.getBody().toString());

        return responseEntity.toString();

    }

    private static String createHash(String value) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(value.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

}