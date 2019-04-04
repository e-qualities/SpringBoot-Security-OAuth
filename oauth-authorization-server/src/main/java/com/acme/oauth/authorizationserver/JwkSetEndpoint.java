package com.acme.oauth.authorizationserver;

import java.net.URI;
import java.security.KeyPair;
import java.security.Principal;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import net.minidev.json.JSONObject;

@FrameworkEndpoint
class JwkSetEndpoint {
    private Map<String, KeyPair> keyPairMapping;
    private IssuerProvider issuerProvider;

    /**
     * Creates a new JWK set endpoint providing
     * access to the JWT public signing keys
     * and the OpenID auto-configuration endpoints.
     * 
     * @param keyPairMapping the keyPair-to-keyID mapping.
     * @param issuer the (request-scoped) Issuer, which will be used to derive the URLs of the auto-configuration endpoints.
     */
    @Autowired
    public JwkSetEndpoint(Map<String, KeyPair> keyPairMapping, IssuerProvider issuerProvider) {
        this.keyPairMapping = keyPairMapping;
        this.issuerProvider = issuerProvider;
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
    
}
