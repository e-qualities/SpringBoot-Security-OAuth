package com.acme.oauth.authorizationserver;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * An introspection endpoint for issued tokens.
 * Simply point your browser to /introspect/<token> to get some debug information.
 * Note: do not offer this for production. 
 */
@FrameworkEndpoint
public class JwtIntrospectionEndpoint {
    
    private TokenStore tokenStore;

    public JwtIntrospectionEndpoint(TokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    @PostMapping("/introspect/{token}")
    @ResponseBody
    public Map<String, Object> introspect(@PathVariable String token) {
        
        OAuth2AccessToken accessToken = tokenStore.readAccessToken(token);
        
        Map<String, Object> attributes = new HashMap<>();
        if (accessToken == null || accessToken.isExpired()) {
            attributes.put("active", false);
            return attributes;
        }

        OAuth2Authentication authentication = tokenStore.readAuthentication(token);

        attributes.put("active", true);
        attributes.put("exp", accessToken.getExpiration().getTime());
        attributes.put("scope", accessToken.getScope().stream().collect(Collectors.joining(" ")));
        attributes.put("sub", authentication.getName());

        return attributes;
    }
}