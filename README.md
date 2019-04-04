# SpringBoot-Security-OAuth
A set of sample projects showing SpringBoot's Security OAuth features. Includes also integration with SAP CP CF.

Table of Contents
=================

   * [Understanding Spring Boot Security OAuth](#understanding-spring-boot-security-oauth)
   * [Understanding Spring Security Versions](#understanding-spring-security-versions)
      * [Spring Cloud Security](#spring-cloud-security)
      * [Maven Dependencies for the Spring Security Frameworks for Spring Boot](#maven-dependencies-for-the-spring-security-frameworks-for-spring-boot)
         * [Spring Security](#spring-security)
         * [Spring Security OAuth 2.0](#spring-security-oauth-20)
   * [Authorization Server](#authorization-server)
      * [Running the Server](#running-the-server)
      * [Implementation](#implementation)
         * [Main Class](#main-class)
         * [Main Security Configurations](#main-security-configurations)
         * [Authorization Server Configurations](#authorization-server-configurations)
         * [User Authentication Configurations](#user-authentication-configurations)
         * [JWT Key Set Endpoints](#jwt-key-set-endpoints)
   * [OAuth 2.0 Resource Server](#oauth-20-resource-server)
   * [OAuth 2.0 Client](#oauth-20-client)
   * [References](#references)

# Understanding Spring Boot Security OAuth

To better understand the contents of this repository, you should know that Spring Boot Security distinguishes three aspects of OAuth:

1. The `OAuth Client`
2. The `Resource Server`
3. The `Authorization Server`

The **Client** is usually an application or service that acts on behalf of a (human) user, and hence needs to receive authorization to perform certain activities on the Resource Server, like looking up, modifying or creating a resource.  

The **Resource Server** provides the actual resources - this could be another service, a remote Web site (e.g. GitHub, Facebook) the Client application provides the user delegated access to. The resources are protected using an OAuth2 token and hence the Resource Server needs to check the existence and validity of an OAuth2 access token before allowing a request from the Client to succeed.

Finally the **Authorization Server** is the component that is used by the Client to retrieve the OAuth2 access token, and used by the Resource Server to validate the token.
The Authorization server interfaces also with the user (usually via a browser) in that it requires the user to be properly authenticated.

# Understanding Spring Security Versions

At the time of writing this, there exist mainly three different Spring frameworks that deal with security. These are:

1. [Spring Security](https://spring.io/projects/spring-security#learn) - the foundation for all security in Spring and Spring Boot. It is currently available in version [`5.1.5`](https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/).
1. [Spring Security OAuth](https://spring.io/projects/spring-security-oauth#learn) exists in version `2.3.5` and was originally developed as an add-on to Spring Security, which - formerly - had no first class OAuth support.  
   Spring Security OAuth is the foundation for Spring Security OAuth 1.0 and ... 
1. [Spring Security OAuth 2.0](https://projects.spring.io/spring-security-oauth/docs/oauth2.html) - also developed as an add-on to Spring Security when it did not have OAuth 2.0 support yet.

Spring Security and Spring Security OAuth are currently (April 2019) undergoing some changes, and there is a certain feature overlap bewteen them.

At the time of writing this, [Spring Security](https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/) is available in version `5.1.5`.
At the same time [Spring Security OAuth](https://spring.io/projects/spring-security-oauth#learn) exists in version `2.3.5`, which originally was developed as an add-on to Spring Security which - formerly - had no first class OAuth support.
As part of Spring Security OAuth, there exists [Spring Security OAuth 2.0](https://projects.spring.io/spring-security-oauth/docs/oauth2.html) - also developed as an add-on to Spring Security when it did not have OAuth 2.0 support yet.

Currently, [Spring Security](https://spring.io/projects/spring-security#learn) is embedding **first class OAuth 2.0 support**, thus - in the midterm - rendering [Spring Security OAuth](https://spring.io/projects/spring-security-oauth#learn) and [Spring Security OAuth 2.0](https://projects.spring.io/spring-security-oauth/docs/oauth2.html) relevant only for legacy projects.

However, as of [Spring Security `5.1.5`](https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/) there is only first class OAuth 2.0 support for `OAuth Client` and `Resource Server`.  
`Authorization Server` is not yet available, and hence [Spring Security OAuth 2.0](https://projects.spring.io/spring-security-oauth/docs/oauth2.html) is still required if one wants to realize an `Authorization Server`.

If, like in our case, you want to use [Spring Security OAuth 2.0](https://projects.spring.io/spring-security-oauth/docs/oauth2.html) in combination with Spring Boot, you can find integrations (autoconfigurations) and documentation in [OAuth2 Boot](https://docs.spring.io/spring-security-oauth2-boot/docs/current-SNAPSHOT/reference/htmlsingle/). Keep in mind that this is only required if you are writing an OAuth2 `Authorization Server`, and if you are doing it with Spring Boot.

For more details about which features are supported in which Spring Security / Security OAuth version, see this [Spring Security OAuth 2.0 Feature Matrix](https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Features-Matrix).

## Spring Cloud Security

[Spring Cloud Security](https://spring.io/projects/spring-cloud-security) is building on Spring Boot and Spring Security OAuth2 to quickly create systems that implement common patterns like single sign on, token relay and token exchange.
Key features include:

* Relay SSO tokens from a front end to a back end service in a Zuul proxy
* Relay tokens between resource servers
* An interceptor to make a Feign client behave like OAuth2RestTemplate (fetching tokens etc.)
* Configure downstream authentication in a Zuul proxy

If your app is using Spring Cloud Netlix Zuul as an API Gateway / Proxy then you can ask it to forward OAuth2 access tokens downstream to the services it is proxying.  
Thus the your Spring Boot app can be enhanced simply like this:

```java
@SpringBootApplication
@EnableOAuth2Sso
@EnableZuulProxy
class Application {

}
```

As a result it will (in addition to logging the user in and retrieving a token) pass the authentication token downstream to the proxied services.  
If those services are implemented with `@EnableResourceServer` then they will get a valid token in the correct header. [More Details](https://cloud.spring.io/spring-cloud-static/spring-cloud-security/2.1.0.RELEASE/single/spring-cloud-security.html).

For an in depth walkthrough of how to use Zuul in Cloud Foundry for proxying and as an API gateway, see the [Spring Netflix Cloud](https://github.com/e-qualities/Spring-Netflix-Cloud/tree/master-with-zuul-hystrix-turbine-ribbon-cf-canarytesting) repository.

## Maven Dependencies for the Spring Security Frameworks for Spring Boot

In this section we will provide the maven dependencies of the frameworks differentiated above. We will list the dependencies relevant for a Spring Boot project. The dependencies may differ slightly, if you are creating a plain Spring project.

An easy way to set up a Spring Boot project and add the required dependencies is to use the [Spring Initializr](https://start.spring.io/) Web-based project generator.

You need to have the Spring Boot Starter Parent as your `pom.xml`'s parent POM.

```xml
<parent>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-parent</artifactId>
  <version>2.1.4.RELEASE</version>
  <relativePath/>
</parent>
```

### Spring Security

Dependencies for working with the entire Spring Security 5.1.5 packages in Spring Boot: 

```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```
This is equivalent to adding `Security` as dependency in [Spring Initializr](https://start.spring.io/).
For the exact list of Spring Security 5.1.5 dependencies this includes, see [`spring-boot-starter-oauth2-client` on maven central](https://search.maven.org/artifact/org.springframework.boot/spring-boot-starter-security/2.1.4.RELEASE/jar).

Dependencies for realising an `OAuth Client` with Spring Security 5.1.5 and Spring Boot: 

```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>
```
This is equivalent to adding `OAuth2 Client` as dependency in [Spring Initializr](https://start.spring.io/).
For the exact list of Spring Security 5.1.5 dependencies this includes, see [`spring-boot-starter-oauth2-client` on maven central](https://search.maven.org/artifact/org.springframework.boot/spring-boot-starter-oauth2-client/2.1.4.RELEASE/jar).

Dependencies for realising a `Resource Server` with Spring Security 5.1.5 and Spring Boot:

```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```
This is equivalent to adding `OAuth2 Resource Server` as dependency in [Spring Initializr](https://start.spring.io/).
For the exact list of Spring Security 5.1.5 dependencies this includes, see [`spring-boot-starter-oauth2-resource-server` on maven central](https://search.maven.org/artifact/org.springframework.boot/spring-boot-starter-oauth2-resource-server/2.1.4.RELEASE/jar).

### Spring Security OAuth 2.0

Spring Security OAuth 2.0 depends on Spring Security, so the maven dependencies for Spring Security listed above need to be part of your `pom.xml` as well.

Dependencies for Spring Security OAuth 2.0:

```xml
<dependency>
  <groupId>org.springframework.security.oauth</groupId>
  <artifactId>spring-security-oauth2</artifactId>
  <artifactId>2.3.5.RELEASE</artifactId>
</dependency>
```

Dependencies for Spring Boot Integration of Spring Security OAuth 2.0 via auto-configuration.

```xml		
<dependency>
  <groupId>org.springframework.security.oauth.boot</groupId>
  <artifactId>spring-security-oauth2-autoconfigure</artifactId>
</dependency>
```

See [Spring Boot Integration for Spring Security OAuth 2.0](https://docs.spring.io/spring-security-oauth2-boot/docs/current-SNAPSHOT/reference/htmlsingle/) for more information.

# Authorization Server

Project `oauth-authorization-server` implements an OAuth2.0 Authorization Server.
Follows the documentation described [here](https://docs.spring.io/spring-security-oauth2-boot/docs/current-SNAPSHOT/reference/htmlsingle/#boot-features-security-oauth2-authorization-server) and is based on this [Spring Security Sample](https://github.com/spring-projects/spring-security/tree/master/samples/boot/oauth2authorizationserver).

The OAuth 2.0 flow currently implemented is the **Authorization Code Grant** (`authorization_code`) flow, including JWT tokens as the format for the authorization tokens. For a sample that implements the **Password Grant** (`password`) flow, see this [sample](https://github.com/spring-projects/spring-security/tree/master/samples/boot/oauth2authorizationserver).

## Running the Server

To run the server, proceed as follows:
1. `cd oauth-authorization-server`
2. `mvn clean package`
3. `java -jar target/oauth-authorization-server-0.0.1-SNAPSHOT.jar` 

This will start the server on port 10080 (as configured in the server's `application.yml`)

Once running, you can point your browser at the following URL: [`http://localhost:10080/oauth/authorize?grant_type=authorization_code&response_type=code&client_id=client-1&state=1234&redirect_uri=http%3A%2F%2Flocalhost%3A10090%2Foauth%2Flogin%2Fclient-app`](http://localhost:10080/oauth/authorize?grant_type=authorization_code&response_type=code&client_id=client-1&state=1234&redirect_uri=http%3A%2F%2Flocalhost%3A10090%2Foauth%2Flogin%2Fclient-app).  
Note that the `redirect_uri` is encoded in the URL and has to match one of the URIs registered in `AuthorizationServerConfigurations.java`.

You will be asked to authenticate (User: `TestUser`, Password: `test1234`), and once successful will be redirected to `http://localhost:10090/oauth/login/client-app?code=Duek6y&state=1234` (which is the configured default `redirectURI`). The redirect URI should normally point at a particular resource server.

Once you have authenticated, you will be redirected several times, finally being redirected to the `redirect_uri` given in the original request URL like this: `http://localhost:10090/oauth/login/client-app?code=jmFRo7&state=1234`.  
This URL contains the authorization code, which can be exchanged for a (JWT) token, with the following HTTP request.
Note, that the `code` is given in the request data!

```
curl -X POST \
  'http://localhost:10080/oauth/token' \
   -H 'Authorization: Basic Y2xpZW50LTE6Y2xpZW50LTEtc2VjcmV0' \
   -H 'content-type: application/x-www-form-urlencoded' \
   -d 'grant_type=authorization_code&client_id=client-1&client_secret=client-1-secret&code=jmFRo7&redirect_uri=http://localhost:10090/oauth/login/client-app'
```

The result should look as follows:

```json
{
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NTYwMjY4NTAsInVzZXJfbmFtZSI6IlRlc3RVc2VyIiwiYXV0aG9yaXRpZXMiOlsiUk9MRV9VU0VSIl0sImp0aSI6ImVmOWVmMWM2LWQyNGMtNDUwYy1iMzZiLTE1NWJhNTBkODliOSIsImNsaWVudF9pZCI6ImNsaWVudC0xIiwic2NvcGUiOlsicmVhZF9yZXNvdXJjZSJdfQ.Q-HGMySSheRUTpx7eKQzioakqsdsSReWjBjpM5zqx_HknjDwaLk-2zjaLwFnLeAPWmX2qmss_Jr8CT7gYsBQUHbcPO3x8GxH5fMB6-ZRuV35Y8DZs6sux1lbDUeVeTEKl-asFDUdY5NsQqsTxpuwaNBtnBvxYRNPJrOrhETCdMiPF7pP1-FokCIj8u13BmnJUPObxzqoZPHnjKHDjkLKcGGClQKMKid1eUAquXTD61QAwMx2oHgkFTPsjppR2BbxgdxoKIzwbLha2Yg83cgoHEJU8V1NMMLr1vvlidXV9sFdRu7_HLgeBs7jsaZC9Uw36Isha1NAHOwnMngko3ADGQ",
    "token_type": "bearer",
    "expires_in": 3599,
    "scope": "read_resource",
    "jti": "ef9ef1c6-d24c-450c-b36b-155ba50d89b9"
}
```

Note that there is also a collection of Postman requests available in `./Postman-Requests/Spring Authz Server Requests.postman_collection.json`.

Finally note, that the server also advertises its public keys for JWT signature validation under `http://localhost:10080/.well-known/jwks.json`.

## Implementation

### Main Class

The main class is `AuthorizationServer`
```java
@SpringBootApplication
public class AuthorizationServer {

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationServer.class, args);
	}
}
```

### Main Security Configurations

Class `ApplicationSecurityConfigurations` contains application-wide security configurations - mainly a bean that exposes a public/private `KeyPair` used for JWT signing and a `PasswordEncoder` instance which is used to one-way encode passwords, so that they are not stored in plain text. The KeyPair can be generated on the fly at startup or read from a Java keystore file.

```java
@Configuration
public class ApplicationSecurityConfigurations {

    @Bean
    public Map<String, KeyPair> publicPrivateKeyPair() throws NoSuchAlgorithmException {
        KeyPair keyPair = loadKeyPairFromFile(); 
        
        HashMap<String, KeyPair>  keyPairMap = new HashMap<>();
        keyPairMap.put("key-id-0", keyPair);
        return keyPairMap;
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
    
    private KeyPair loadKeyPairFromFile() {
        KeyStoreKeyFactory keyStoreKeyFactory = 
          new KeyStoreKeyFactory(new ClassPathResource("jwtKeys.jks"), "password".toCharArray());
        return keyStoreKeyFactory.getKeyPair("jwtKeys");
    }
}
```

The `KeyPair` is exposed via a map that maps a key ID to the given `KeyPair`. That key ID is publised by a JWK endpoint and is used to tell JWT token consumers which key(s) were used to sign the JWT token. The key ID is also encoded into the JWT token's header by the `kid` property. This allows consumers to pick the correct public key from the JWK endpoint and use it to verify the JWT signature with.

The keystore file used when loading the `KeyPair` from the file system is located in `src/main/resources` and was generated using the following commands:
```
keytool -genkey -alias jwtKeys -keyalg RSA -sigalg SHA256withRSA -keysize 2048 -validity 3650 -keypass password -keystore jwtKeys.jks -storepass password
keytool -importkeystore -srckeystore jwtKeys.jks -destkeystore jwtKeys.jks -deststoretype pkcs12
```
You can find more information [here](http://javaevangelist.blogspot.com/2016/08/how-to-generate-sha-2-sha-256-self.html).

### Authorization Server Configurations

Class `AuthorizationServerConfigurations` contains the actual configurations of the Authorization Server. In particular, this is where OAuth Clients (i.e. credentials for client applications) are defined.  
This can be done in memory ...

```java
private void configureInMemoryOAuthClients(ClientDetailsServiceConfigurer clients) throws Exception {
    // @formatter:off
    clients
    // Use a data store to persist OAuth Client definitions 
    // instead of keeping them inMemory().
    .inMemory()
        .withClient("client-1")
            .secret(passwordEncoder.encode("client-1-secret"))
            .scopes("read_resource", "write_resource")
            .authorizedGrantTypes("authorization_code")
            .redirectUris("http://localhost:10090/oauth/login/client-app", "http://localhost:8888/login") // register a redirect URI the client may provide.
            .autoApprove(true)
            .accessTokenValiditySeconds(3600)
            .refreshTokenValiditySeconds(300);
        //.resourceIds("resource-1", "resource-2", "resource-3")
    // @formatter:on
}
```

... or by reading the information from a `DataSource` (e.g. a database):

```java
@Autowired
DataSource dataSource;

private void configurePersistentOAuthClients(ClientDetailsServiceConfigurer clients) throws Exception {
    // @formatter:off
    clients
        // Use a data store to persist OAuth Client definitions 
        // instead of keeping them inMemory().
        .jdbc(dataSource) // put an //@Autowired DataSource dataSource here.
        .passwordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder());
    // @formatter:on
}
```

Also in this class, the JWT creation is configured. By default, the `OAuth 2.0 Authorization Code Grant` flow does not define the format of the OAuth 2.0 Token that will be returned to serve as an authentication proof and authorization bearer.  
To make the server return JWT tokens, it needs to be configured to do so.

This mainly happens in the following methods:

```java
private IssuerProvider issuerProvider;
...

@Bean
@Primary
public AuthorizationServerTokenServices tokenServices() {
    DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
    defaultTokenServices.setTokenStore(tokenStore());
    defaultTokenServices.setSupportRefreshToken(true);
    defaultTokenServices.setAuthenticationManager(authenticationManager);
    return defaultTokenServices;
}

@Bean
public TokenStore tokenStore() {
    return new JwtTokenStore(accessTokenConverter());
}

@Override
public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
    security
        // permit all access to /oauth/token_key
        .tokenKeyAccess("permitAll()")
        // permit only trusted resources access to /oauth/check_token
        .checkTokenAccess("hasAuthority('ROLE_TRUSTED_CLIENT')");  
}

@Override
public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
    // @formatter:off
    endpoints
        .authenticationManager(authenticationManager)
        .accessTokenConverter(accessTokenConverter())
        .tokenStore(tokenStore());
    // @formatter:on
}

@Bean
public JwtAccessTokenConverter accessTokenConverter() {
    
    Map<String, String> headers = new HashMap<String, String>();
    Entry<String, KeyPair> keyPairEntry = keyPairMapping.entrySet().iterator().next();
    headers.put(KID, keyPairEntry.getKey());
    
    HeadersEncodingJwtAccessTokenConverter converter = new HeadersEncodingJwtAccessTokenConverter(headers);
    converter.setKeyPair(keyPairEntry.getValue());
    
    // set a custom user token converter that properly encodes the
    // user name of the authenticated user as the `sub` claim in the JWT token
    // as should be the case, nowadays.
    DefaultAccessTokenConverter accessTokenConverter = new DefaultAccessTokenConverter();
    accessTokenConverter.setUserTokenConverter(new SubjectAndIssuerAttributeUserTokenConverter(issuerProvider));
    converter.setAccessTokenConverter(accessTokenConverter);
    
    return converter;
}
```

In particular note the `accessTokenConverter()` bean definition. In here, we return a custom JwtAccessTokenConverter named [`HeadersEncodingJwtAccessTokenConverter`](./oauth-authorization-server/src/main/java/com/acme/oauth/authorizationserver/HeadersEncodingJwtAccessTokenConverter.java).
This class is responsible for converting the user authentication and authorization into a JWT format.   
`HeadersEncodingJwtAccessTokenConverter` derives from `JwtAccessTokenConverter` and additionally enables the encoding of additional JWT header fields. The latter is required to transport the ID of the used signing key back to clients, so that they can read the information from the JWT header and look up the correct public key via the `/.well-known/jwks.json`.

Furthermore, we add an `AccessTokenConverter` which gets a `UserTokenConverter` that encodes the `sub` (subject) and `iss` (issuer) claims into the JWT. This needs to be added manually, since the Spring Security OAuth2 Authorization Server does not include this.
The `UserTokenConverter` is an instance of class `SubjectAndIssuerAttributeUserTokenConverter`, which we created ourselves. It gets an `IssuerProvider` instance which is an injected bean that has `@RequestScope`, i.e. a new instance is created for every request.  This is to make sure that the issuer URI (derived from the incoming request URL) matches the host name of the Authorization Server, no matter where it is running. 

```java
private class SubjectAndIssuerAttributeUserTokenConverter extends DefaultUserAuthenticationConverter {
        
    private static final String SUBJECT_CLAIM = "sub";
    private static final String ISSUER_CLAIM = "iss"; 
    private IssuerProvider issuerProvider;
    
    /**
        * A token converter that encodes the subject ({@code sub}) and 
        * Issuer ({@code iss}) into the JWT token. 
        * Uses a request-scoped issuer to derive the issuer URI from the
        * incoming HTTP request.
        * @param issuer the request-scoped Issuer.
        * 
        * @see RequestScopedBeansConfiguration
        */
    public SubjectAndIssuerAttributeUserTokenConverter(IssuerProvider issuerProvider) {
        this.issuerProvider = issuerProvider; 
    }
    
    @Override
    public Map<String, ?> convertUserAuthentication(Authentication authentication) {
        Map<String, Object> response = new LinkedHashMap<String, Object>();
        response.put(SUBJECT_CLAIM, authentication.getName());
        response.put(ISSUER_CLAIM, issuerProvider.getIssuer().getValue());
        
        if (authentication.getAuthorities() != null && !authentication.getAuthorities().isEmpty()) {
            response.put(AUTHORITIES, AuthorityUtils.authorityListToSet(authentication.getAuthorities()));
        }
        return response;
    }
}
```

### User Authentication Configurations

Since the OAuth 2.0 `Authorization Code Grant` flow includes the need for user authentication (before an authorization token can be created), we have implemented the user authentication as part of the AuthorizationServer. This is done in class `WebSecurityConfigurations`:

```java
@Configuration
public class WebSecurityConfigurations extends WebSecurityConfigurerAdapter {
    
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    public WebSecurityConfigurations(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }
    
    @Bean
    @Override
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
            User.withUsername("TestUser")
                .password(passwordEncoder.encode("test1234"))
                .roles("USER")
                .build());
        
        // or: define the users that may log in using a database.
        // return new JdbcUserDetailsManager(this.dataSource);  
    }
}
```
This will allow users to log in using the (hardcoded) credentials using the `http://localhost:10080/login` endpoint. Of course, credentials could also be read from a user database.

### JWT Key Set Endpoints

Class `JwkSetEndpoint` exposes two custom endpoints. One is for JWT token key sets. These will be required by `OAuth Client`s and `ResourceServer`s written with Spring Security 5.1 and later to look up the (potentially multiple) public keys that may have been used for signing the JWT token (e.g. via key rotation). The second endpoint is used to publish Open ID configuration metadata that `OAuthClient`s and `ResourceServer`s can use for auto-configuration.

```java
@FrameworkEndpoint
class JwkSetEndpoint {

    private Map<String, KeyPair> keyPairMapping;

    @Autowired
    public JwkSetEndpoint(Map<String, KeyPair> keyPairMapping) {
        this.keyPairMapping = keyPairMapping;
    }

    @GetMapping("/.well-known/jwks.json")
    @ResponseBody
    public JSONObject getKeySet(Principal principal) {
        Entry<String, KeyPair> keyMapEntry = keyPairMapping.entrySet().iterator().next();
        String keyId = keyMapEntry.getKey();
        KeyPair keyPair = keyMapEntry.getValue();
        
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAKey key = new RSAKey.Builder(publicKey)
                                .keyID(keyId)
                                .algorithm(JWSAlgorithm.RS256)
                                .keyUse(KeyUse.SIGNATURE)
                                .build();
        
        JWKSet jwkSet = new JWKSet(key);
       
        // If you wanted to add the public key info in plain
        // you could do something like this...
        //
        // String publicKeyInfo = "-----BEGIN PUBLIC KEY-----\n" + publicKey.getEncoded() + "\n-----END PUBLIC KEY-----";
        //
        // ...then add the key info as a "value" property in the first key of the `keys` array.
        return jwkSet.toPublicJWKSet().toJSONObject();
    }
    
    @GetMapping("/.well-known/openid-configuration")
    @ResponseBody
    public JSONObject getOpenIdConfiguration(Principal principal) {
        Issuer issuer = new Issuer("http://localhost:10080");
        URI jwksetUri = URI.create("http://localhost:10080/.well-known/jwks.json");
        
        List<SubjectType> subjectTypes = new ArrayList<SubjectType>(); 
        subjectTypes.add(SubjectType.PUBLIC);
        
        OIDCProviderMetadata metadata = new OIDCProviderMetadata(issuer, subjectTypes, jwksetUri);
        metadata.setAuthorizationEndpointURI(URI.create("http://localhost:10080/oauth/authorize"));
        metadata.setTokenEndpointURI(URI.create("http://localhost:10080/oauth/token"));
        // ... and plenty more. 
        // For example, see: https://authentication.eu10.hana.ondemand.com/.well-known/openid-configuration
        return metadata.toJSONObject();
    }
}
```

This will allow `ResourceServer`s and `OAuthClient` applications to look up the public keys of the Authorization server and use them for validating the JWT token signature. The endpoints will be available under `http://localhost:10080/.well-known/jwks.json` and `http://localhost:10080//.well-known/openid-configuration`, but you could of course change them simply by changing the `@GetMapping` paths.

**Note:** we only use a single public key in this example. If your server implemented a key-rotation strategy, you could publicize more keys, of course. This is common practice and also used by SAP's XSUAA for example.

Calling the endpoint will return a JSON similar to this one:

```json
{
  keys: [
    {
      kty: "RSA",
      e: "AQAB",
      kid: "key-1",
      use: "sig",
      alg: "RS256",
      n: "lh_LV7FNcUhnj560gKTmRrNQh07IGMk4DWnuVW5W04Xqt1bEex4p7JsBdegMAdsAaUktkwgD-E_bHEeeaLHil2sw-xBBiJJAKGuR9C1YMb-aQ7_51KoBPsNPKZzYlIl37_CB_F7YSUV_ZehYFM9ohGa9PhldU5bvDDaTDSNgrQoaIFmCYhqxnquzubowfS173TabZzqXNdx7udG0v3sIz8wD7K451B8YN885Fmq43pKRYeN04ff8e9iWwv03cowb4vlnx-oXkxk5T61QFckfzI0PVBkNtgdPF1zZmuxQgj-yOflxvAdojFaV0NxJPiH_2KYlvI9Dc9P8nqmE5REQuw"
    }
  ]
}
```
Note that this is the correct, standards-compliant format. SAP's XSUAA exposes a similar JSON but including an additional `value` property that holds the public key information in the `----- BEGIN PUBLIC KEY -----` format. This is merely for documentation / reference purposes.

Access to the additional JWT key set endpoint needs to be allowed. This is done in class `WebSecurityConfigurations`. 
Here, we allow unauthenticated access to the `/.well-known/jwks.json` endpoint.

```java
@Configuration
class WebSecurityConfigurations extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .mvcMatchers("/.well-known/jwks.json").permitAll()
                .mvcMatchers("/.well-known/openid-configuration").permitAll()
                .anyRequest().authenticated()
                .and()
            .httpBasic()
                .and()
            .csrf()
                .ignoringAntMatchers("/introspect/**");
                
    }
}
```

Note that Spring Security OAuth 2.0 Authorization Server supports (out of the box) the following endpoints:

* `/oauth/authorize` (the authorization endpoint)
* `/oauth/token` (the token endpoint)
* `/oauth/confirm_access` (user posts approval for grants here)
* `/oauth/error` (used to render errors in the authorization server)
* `/oauth/check_token` (used by Resource Servers to decode access tokens)
* `/oauth/token_key` (exposes (one) public key for token verification if using JWT tokens).

As described [here](http://projects.spring.io/spring-security-oauth/docs/oauth2.html#configuring-the-endpoint-urls). 

To expose the `/oauth/check_token` and `/oauth/token_key`, we need to explicitly do so (since access to them is denied by default) in class `AuthorizationServerConfigurations`:

```java
@Override
public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
    security
        // permit all access to /oauth/token_key
        .tokenKeyAccess("permitAll()")
        // permit only trusted resources access to /oauth/check_token
        .checkTokenAccess("hasAuthority('ROLE_TRUSTED_CLIENT')");  
    // For more expressions see: 
    // https://projects.spring.io/spring-security-oauth/docs/oauth2.html#configuring-an-oauth-aware-expression-handler
}
```

### OpenID Auto-Configuration Endpoint

Authorization Server also exposes the `/.well-known/openid-configuration` endpoint, which exposes all relevant endpoint URIs and can be used by OAuth 2.0 Clients and Resource Servers to auto-configure themselves.
The auto-configuration mechanism relies on the following (matching) information:

1. An `spring.security.oauth2.resourceserver.jwt.issuer-uri` configured in the Client's or Resource Server's `application.yml`
1. The issuer URI in the `iss` claim of the JWT issued by Authorization Server
1. The issuer URI advertised in Authorization Server's `/.well-known/openid-configuration` endpoint.

For example, a **Resource Server**'s configuration might look as follows:

```yaml
spring:
  application:
    name: address-service
  
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://authorization.server.cfapps.com:10080/
```

Authorization Server needs to issue a fitting JWT that needs to contain a matching `iss` claim:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-id-0"
}
{
  "sub": "TestUser",
  "scope": [
    "read_resource",
    "write_resource"
  ],
  "iss": "http://authorization.server.cfapps.com:10080/",
  "exp": 1557489770,
  "authorities": [
    "ROLE_USER"
  ],
  "jti": "d1baca48-c09d-4b6f-8588-bb3b418c8c9f",
  "client_id": "client-1"
}
```

And the Authorization Server's `/.well-known/openid-configuration` endpoint needs to expose a JSON that contains the proper issuer as well:

```json
{
    issuer: "http://authorization.server.cfapps.com:10080/",
    jwks_uri: "http://authorization.server.cfapps.com:10080//.well-known/jwks.json",
    authorization_endpoint: "http://authorization.server.cfapps.com:10080//oauth/authorize",
    token_endpoint: "http://authorization.server.cfapps.com:10080//oauth/token",
    request_parameter_supported: false,
    request_uri_parameter_supported: true,
    require_request_uri_registration: false,
    tls_client_certificate_bound_access_tokens: false,
    subject_types_supported: ["public"],
    claims_parameter_supported: false,
    frontchannel_logout_supported: false,
    backchannel_logout_supported: false
}
```

We make sure, that Authorization Server provides the proper JWT and Open ID Configuration Endpoint contents in class `JwkSetEndpoint`:

```java
@GetMapping("/.well-known/openid-configuration")
@ResponseBody
public JSONObject getOpenIdConfiguration(Principal principal) {
    Issuer issuer = issuerProvider.getIssuer();
    
    String jwksetUriString = issuer.getValue() + "/.well-known/jwks.json";
    String authorizationEndpointUriString = issuer.getValue() + "/oauth/authorize";
    String tokenEndpointUriString = issuer.getValue() + "/oauth/token";
    
    URI jwksetUri = URI.create(jwksetUriString);
    URI authorizationEndpointUri = URI.create(authorizationEndpointUriString);
    URI tokenEndpointUri = URI.create(tokenEndpointUriString);
    
    List<SubjectType> subjectTypes = new ArrayList<SubjectType>(); 
    subjectTypes.add(SubjectType.PUBLIC);
    
    OIDCProviderMetadata metadata = new OIDCProviderMetadata(issuer, subjectTypes, jwksetUri);
    metadata.setAuthorizationEndpointURI(authorizationEndpointUri);
    metadata.setTokenEndpointURI(tokenEndpointUri);
    // ... and plenty more. 
    // For example, see: https://authentication.eu10.hana.ondemand.com/.well-known/openid-configuration
    return metadata.toJSONObject();
}
```
Note, that in this implementation we use an injected `IssuerProvider` bean which we expose as `@RequestScope`d.  
The issuer URI, which is required in the JWT as well as the Open ID auto-configuration JSON is derived from the incoming HTTP request.

Note also, that we are using the issuer URI also for the endpoints of the `/oauth/token` and `/oauth/authorize` as well as the JWKSet endpoint.
That is not strictly necessary. The only values that need to match are that of the JWT `iss` claim, the `issuer` in the Open ID JSON and the `issuer-uri` of the Resource Server OAuth 2.0 configuration.

Once Authorization Server is started, you can point your browser to `http://localhost:10080/.well-known/openid-configuration` to see the auto-configuration JSON in action.

# OAuth 2.0 Resource Server

... coming soon.

# OAuth 2.0 Client

... coming soon.


# References

* [Spring Security 5.1.5](https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/) | [OAuth 2.0 Client](https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#oauth2client)
* [Spring Security OAuth 2.0 Feature Matrix](https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Features-Matrix)
* [Spring Boot Integration for Spring Security OAuth 2.0](https://docs.spring.io/spring-security-oauth2-boot/docs/current-SNAPSHOT/reference/htmlsingle/)
* [Spring Cloud Security](https://spring.io/projects/spring-cloud-security) | [Spring Cloud Security Documentation](https://cloud.spring.io/spring-cloud-static/spring-cloud-security/2.1.0.RELEASE/single/spring-cloud-security.html)
* [Spring Netflix Cloud](https://github.com/e-qualities/Spring-Netflix-Cloud/tree/master-with-zuul-hystrix-turbine-ribbon-cf-canarytesting) Walkthrough
* [Spring Security Authorization Server Sample](https://github.com/spring-projects/spring-security/tree/master/samples/boot/oauth2authorizationserver)
* [Spring Security and Angular JS Samples](https://spring.io/guides/tutorials/spring-security-and-angular-js/)