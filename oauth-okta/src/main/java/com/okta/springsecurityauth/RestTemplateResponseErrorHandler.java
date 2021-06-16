package com.okta.springsecurityauth;

import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.client.ResponseErrorHandler;

import java.io.IOException;

import static org.springframework.http.HttpStatus.Series.CLIENT_ERROR;
import static org.springframework.http.HttpStatus.Series.SERVER_ERROR;

@Component
public class RestTemplateResponseErrorHandler
        implements ResponseErrorHandler {

    @Override
    public boolean hasError(ClientHttpResponse httpResponse)
            throws IOException {

        System.out.println(httpResponse.getStatusCode());
        System.out.println(httpResponse.getStatusText());
        System.out.println(httpResponse.getBody().toString());

        return (httpResponse.getStatusCode().series() == CLIENT_ERROR
                        || httpResponse.getStatusCode().series() == SERVER_ERROR);
    }

    @Override
    public void handleError(ClientHttpResponse httpResponse)
            throws IOException {

        if (httpResponse.getStatusCode().series() == SERVER_ERROR) {
            // handle SERVER_ERROR
            System.out.println(httpResponse.getStatusCode());
            System.out.println(httpResponse.getStatusText());
            System.out.println(httpResponse.getBody().toString());
        } else if (httpResponse.getStatusCode().series() == CLIENT_ERROR) {
            // handle CLIENT_ERROR
            System.out.println(httpResponse.getStatusCode());
            System.out.println(httpResponse.getStatusText());
            System.out.println(httpResponse.getBody().toString());
            if (httpResponse.getStatusCode() == HttpStatus.NOT_FOUND) {
                System.out.println(httpResponse.getStatusCode());
                System.out.println(httpResponse.getStatusText());
                System.out.println(httpResponse.getBody().toString());
            }
        }
    }
}