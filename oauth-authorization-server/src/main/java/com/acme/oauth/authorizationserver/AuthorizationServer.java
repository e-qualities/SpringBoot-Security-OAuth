package com.acme.oauth.authorizationserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Implementation of an OAuth2.0 Authorization Server.
 * This project uses Spring Security OAuth 2.0 (Legacy) and 
 * Spring Boot auto-configuration for Spring Security OAuth 2.0
 * to get this working. 
 * 
 * For more information see here: 
 * https://docs.spring.io/spring-security-oauth2-boot/docs/current-SNAPSHOT/reference/htmlsingle/#boot-features-security-oauth2-authorization-server
 */
 
@SpringBootApplication
public class AuthorizationServer {

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationServer.class, args);
	}
}
