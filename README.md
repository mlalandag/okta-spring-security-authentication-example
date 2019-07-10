# Simple Authentication with Spring Security

This example code is used in the blog post found [here](https://developer.okta.com/blog/2019/05/31/spring-security-authentication)

This example takes you from using [Spring Security](https://spring.io/projects/spring-security) for basic authentication, to form authentication and finally to integrating with Okta using [OAuth 2.0](https://www.oauth.com/).

> [Okta](https://developer.okta.com/) has Authentication and User Management APIs that reduce development time with instant-on, scalable user infrastructure. Okta's intuitive API and expert support make it easy for developers to authenticate, manage, and secure users and roles in any application.

## Run

In the first two examples, you can simply switch into the `basic-auth` and `form-auth` folders respectively and run:

```
./gradlew bootRun
```

For the final example, switch into the `oauth-okta` folder.

You'll need to create an Okta org [here](https://developer.okta.com/signup).

Follow the instructions in the [blog post](https://developer.okta.com/blog/2019/05/31/spring-security-authentication) for creating an application in Okta.

Setup `src/main/resources/application.yml` like so:

```
okta:  
  oauth2:  
    issuer: https://okta.okta.com/oauth2/default  
    client-id: {yourClientID}
    client-secret: {yourClientSecret} 
spring:  
  thymeleaf:  
    cache: false
```

Then, you can run the app as before:

```
./gradlew bootRun
```

## Additional Resources

If you'd like to learn more about Spring Boot, Spring Security, or secure authentication, check out any of these great tutorials:

-   [Get Started with Spring Boot, OAuth 2.0, and Okta](https://developer.okta.com/blog/2017/03/21/spring-boot-oauth)
-   [Add Single Sign-On to Your Spring Boot Web App in 15 Minutes](https://developer.okta.com/blog/2017/11/20/add-sso-spring-boot-15-min)
-   [Secure Your Spring Boot Application with Multi-Factor Authentication](https://developer.okta.com/blog/2018/06/12/mfa-in-spring-boot)
-   [Build a Secure API with Spring Boot and GraphQL](https://developer.okta.com/blog/2018/08/16/secure-api-spring-boot-graphql)

If you want to dive deeper, take a look at the  [Okta Spring Boot Starter GitHub page](https://github.com/okta/okta-spring-boot).

If you have any questions about this post, please add a comment below. For more awesome content, follow  [@oktadev](https://twitter.com/oktadev)  on Twitter, like us [on Facebook](https://www.facebook.com/oktadevelopers/), or subscribe to  [our YouTube channel](https://www.youtube.com/c/oktadev).
