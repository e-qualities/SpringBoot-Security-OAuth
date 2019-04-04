package com.acme.oauth.authorizationserver;

import java.security.KeyPair;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

/**
 * Configuration of the Authorization Server.
 * If this were not provided a meaningful default would be used.
 * However, it is recommended to not use the defaults for production
 * as they don't include credentials encryption nor JWT token handling.
 * 
 * See: https://docs.spring.io/spring-security-oauth2-boot/docs/current-SNAPSHOT/reference/htmlsingle/#oauth2-boot-authorization-server-disable
 * 
 * See: https://projects.spring.io/spring-security-oauth/docs/oauth2.html
 */
@EnableAuthorizationServer
@Configuration
public class AuthorizationServerConfigurations extends AuthorizationServerConfigurerAdapter {

    private static final String KID = "kid";
    
    private AuthenticationManager authenticationManager;
    private Map<String, KeyPair> keyPairMapping;
    private PasswordEncoder passwordEncoder;
    private IssuerProvider issuerProvider;
    
    public AuthorizationServerConfigurations(AuthenticationConfiguration authenticationConfiguration, Map<String, KeyPair> keyPairMapping, PasswordEncoder passwordEncoder, IssuerProvider issuerProvider) throws Exception {
        this.authenticationManager = authenticationConfiguration.getAuthenticationManager();
        this.keyPairMapping = keyPairMapping;
        this.passwordEncoder = passwordEncoder;
        this.issuerProvider = issuerProvider;
    }
    
    /**
     * The AuthorizationServerTokenServices interface defines the operations that are necessary to manage OAuth 2.0 tokens. 
     * 
     * Note the following:
     * - When an access token is created, the authentication must be stored so that resources accepting the access token can reference it later.
     * - The access token is used to load the authentication that was used to authorize its creation.
     * 
     * When creating your AuthorizationServerTokenServices implementation, you may want to consider using the <code>DefaultTokenServices</code> which has many strategies 
     * that can be plugged in to change the format and storage of access tokens. By default it creates tokens via random value and handles everything except 
     * for the persistence of the tokens which it delegates to a <code>TokenStore</code>. 
     * The default store is an in-memory implementation, but there are some other implementations available. 
     * Here's a description with some discussion of each of them:
     * 
     * - The default InMemoryTokenStore is perfectly fine for a single server (i.e. low traffic and no hot swap to a backup server in the case of failure). 
     *   Most projects can start here, and maybe operate this way in development mode, to make it easy to start a server with no dependencies.
     *   
     * - The JdbcTokenStore is the JDBC version of the same thing, which stores token data in a relational database. 
     *   Use the JDBC version if you can share a database between servers, either scaled up instances of the same server if there is only one, 
     *   or the Authorization and Resources Servers if there are multiple components. To use the JdbcTokenStore you need "spring-jdbc" on the classpath.
     *   
     * - The JSON Web Token (JWT) version of the store encodes all the data about the grant into the token itself (so no back end store at all which is a significant advantage).
     *   One disadvantage is that you can't easily revoke an access token, so they normally are granted with short expiry and the revocation is handled at the refresh token. 
     *   Another disadvantage is that the tokens can get quite large if you are storing a lot of user credential information in them. 
     *   The JwtTokenStore is not really a "store" in the sense that it doesn't persist any data, but it plays the same role of translating between token values and authentication 
     *   information in the DefaultTokenServices.
     *   
     * NOTE: the schema for the JDBC service is not packaged with the Spring Security OAuth2  library (because there are too many variations you might like to use in practice), 
     * but there is an example you can start from in the test code in github. Be sure to @EnableTransactionManagement to prevent clashes between client apps competing for the 
     * same rows when tokens are created. Note also that the sample schema has explicit PRIMARY KEY declarations - these are also necessary in a concurrent environment.

     * @return
     * @See: https://projects.spring.io/spring-security-oauth/docs/oauth2.html
     */
    @Bean
    @Primary
    public AuthorizationServerTokenServices tokenServices() {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore());
        defaultTokenServices.setSupportRefreshToken(true);
        defaultTokenServices.setAuthenticationManager(authenticationManager);
        return defaultTokenServices;
    }
    
    /**
     * A TokenStore is used to store a generated Authorization Token so that 
     * clients / resource servers can later fetch it.
     * In the case JWT tokens are used, the JWT token contains all the authorization
     * information, and hence the token does not need to be "stored" anywhere.
     * 
     * We are using the JwtTokenStore implementation here, which plays the role of 
     * a token store but does not actually persist it.
     * 
     * It is initialized with an accessTokenConverter which is used to
     * convert the generated authorization token into a JWT token.
     * 
     * @return the JwtTokenStore.
     */
    @Bean
    public TokenStore tokenStore() {
        
        // To use JWT tokens you need a JwtTokenStore in your Authorization Server. 
        // The Resource Server also needs to be able to decode the tokens so the 
        // JwtTokenStore has a dependency on a JwtAccessTokenConverter, and the same 
        // implementation is needed by both the Authorization Server and the Resource Server. 
        // The tokens are signed by default, and the Resource Server also has to be able to 
        // verify the signature, so it either needs the same symmetric (signing) key as the 
        // Authorization Server (shared secret, or symmetric key), or it needs the public key 
        // (verifier key) that matches the private key (signing key) in the Authorization Server
        // (public-private or asymmetric key). 
        return new JwtTokenStore(accessTokenConverter());
    }

    /**
     * 
     * @return
     */
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
    
    /**
     * Configuration of OAuth Clients.
     * Clients can be declared in memory or stored in a database.
     * ClientDetailsServiceConfigurer: A configurer that defines the client details service. 
     *                                 Client details can be initialized, or you can just refer to an existing store.
     */
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        
        configureInMemoryOAuthClients(clients);
        
        // ...or for persistent storage of OAuth Client definitions:
        
        //configurePersistentOAuthClients(clients);  
    }
    
    /**
     * Inherited from AuthorizationServerConfigurerAdapter.
     * Check the method parameter for configuration options.
     * AuthorizationServerSecurityConfigurer: Defines the security constraints on the token endpoint.
     * 
     * @See: https://stackoverflow.com/questions/45767147/how-to-use-authorizationserversecurityconfigurer
     * 
     * @See: http://projects.spring.io/spring-security-oauth/docs/oauth2.html#resource-server-configuration
     */
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
    
    /**
     * Inherited from AuthorizationServerConfigurerAdapter.
     * Check the method parameter for configuration options.
     * AuthorizationServerEndpointsConfigurer: Defines the authorization and token endpoints and the token services.
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        // @formatter:off
        endpoints
            .authenticationManager(authenticationManager)
            .accessTokenConverter(accessTokenConverter())
            .tokenStore(tokenStore());
        // @formatter:on
    }

    /**
     * In-memory definition of OAuth clients that are eligible to 
     * contact this Authorization Server. This configuration overrides
     * the client configurations in application.yml 
     * 
     * @param clients
     * @throws Exception
     */
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
    
    /**
     * @param clients
     * @throws Exception
     */
    @SuppressWarnings("unused")
    private void configurePersistentOAuthClients(ClientDetailsServiceConfigurer clients) throws Exception {
        
        // See: http://blog.marcosbarbero.com/centralized-authorization-jwt-spring-boot2/
        
        // @formatter:off
        clients
            // Use a data store to persist OAuth Client definitions 
            // instead of keeping them inMemory().
            .jdbc(/*dataSource*/ null) // put an //@Autowired DataSource dataSource here.
            .passwordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder());
        // @formatter:on
    }
    
    /**
     * Legacy Authorization Server does not support a custom name for the user parameter, so we'll need
     * to extend the default. By default, it uses the attribute {@code user_name} in the JWT. 
     * However, it would be better to adhere to the {@code sub} property defined in the
     * <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JWT Specification</a>.
     * 
     * Additionally, this will place any granted (web-security) authorities / roles of the user
     * to the `authorities` (NOT scopes) property inside the JWT token. 
     * 
     * It will also encode the Issuer into the {@code iss} claim of the JWT token.
     */
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
}
