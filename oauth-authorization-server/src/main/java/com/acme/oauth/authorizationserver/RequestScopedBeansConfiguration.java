package com.acme.oauth.authorizationserver;

import java.net.URI;
import java.net.URISyntaxException;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.web.context.annotation.RequestScope;

import com.nimbusds.oauth2.sdk.id.Issuer;

@Configuration
public class RequestScopedBeansConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(RequestScopedBeansConfiguration.class);
    
    /**
     * Returns a new Issuer instance for every request.
     * This is important, since the request is required to
     * derive the Issuer URI. The Issuer URI will be added 
     * to a JWT token as the {@code iss} claim, and needs to
     * match that advertised in the /.well-known/openid-configuration
     * endpoint. It also needs to match the OAuth 2.0 Client's
     * {@code issuer-uri} configuration in the client's applciation.yml. 
     * @param request the incoming HTTP request.
     * @return the Issuer.
     */
    @Bean
    @RequestScope(proxyMode = ScopedProxyMode.INTERFACES)
    public IssuerProvider issuerProvider(HttpServletRequest request) {
        
        try {
            URI uri = URI.create(request.getRequestURL().toString());
            URI issuerUri = new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), null, null, null);
            Issuer issuer = new Issuer(issuerUri); 
                    
            logger.debug("Using issuer: {}", issuer.getValue());
            
            return new IssuerProviderImpl(issuer);
        } catch (URISyntaxException e) {
            logger.error("FATAL Error! Exception thrown when trying to create URI that is used in JWT iss claim. This will most likely fail auto-configuration of OAuth 2.0 clients and resource servers, since iss-claim will be wrong.", e);
            Issuer issuer = new Issuer("http://wrong-issuer-host-error");
            logger.info("Using default value for issuer: {}", issuer);
            return new IssuerProviderImpl(issuer);
        } 
    }
    
    private static class IssuerProviderImpl implements IssuerProvider {
        private Issuer issuer;
        
        public IssuerProviderImpl(Issuer issuer) {
            this.issuer = issuer;
        }

        @Override
        public Issuer getIssuer() {
            return issuer;
        }
    }
}
