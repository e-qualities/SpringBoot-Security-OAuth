package com.acme.oauth.authorizationserver;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Map;

import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.Signer;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.util.Assert;

public class HeadersEncodingJwtAccessTokenConverter extends JwtAccessTokenConverter {

    private JsonParser objectMapper = JsonParserFactory.create();
    private String verifierKey = new RandomValueStringGenerator().generate();
    private Signer signer = new MacSigner(verifierKey);
    private Map<String, String> jwtHeaders;
    
    public HeadersEncodingJwtAccessTokenConverter(Map<String, String> jwtHeaders) {
        Assert.notNull(jwtHeaders, "Error! Jwt headers must not be null");
        this.jwtHeaders = jwtHeaders;    
    }
    
    @Override
    protected String encode(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        String content;
        try {
            content = objectMapper.formatMap(getAccessTokenConverter().convertAccessToken(accessToken, authentication));
        }
        catch (Exception e) {
            throw new IllegalStateException("Cannot convert access token to JSON", e);
        }
        
        String token = JwtHelper.encode(content, signer, jwtHeaders).getEncoded();
        return token;
    }

    @Override
    public void setSigner(Signer signer) {
        super.setSigner(signer);
        this.signer = signer;
    }

    @Override
    public void setKeyPair(KeyPair keyPair) {
        super.setKeyPair(keyPair);
        PrivateKey privateKey = keyPair.getPrivate();
        signer = new RsaSigner((RSAPrivateKey) privateKey);
    }

    @Override
    public void setSigningKey(String key) {
        super.setSigningKey(key);
        key = key.trim();
        if (key.startsWith("-----BEGIN")) {
            signer = new RsaSigner(key);
        }
        else {
            signer = new MacSigner(key);
        }
    }
}
