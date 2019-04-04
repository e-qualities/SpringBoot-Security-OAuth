package com.acme.oauth.authorizationserver;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Provider.Service;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeSet;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

/**
 * Spring Configuration class containing the 
 * application-wide security configurations.
 * This includes a public/private key pair used 
 * for signing JWT tokens and a PasswordEncoder
 * used to one-way-encode passwords.  
 */
@Configuration
public class ApplicationSecurityConfigurations {

    /**
     * The public/private KeyPair used to sign 
     * JWT tokens with. Returns a map mapping a key ID to a public/private key pair.
     * The key ID will be used in a JWK set to identify the key pair used for
     * signing the JWT token. The key ID will also be encoded as `kid` inside the 
     * JWT token's header.
     * @return the key pair map, mapping a key id to a key pair. 
     * @throws NoSuchAlgorithmException in case the Key algorithm does not exist.
     */
    @Bean
    public Map<String, KeyPair> publicPrivateKeyPair() throws NoSuchAlgorithmException {
        KeyPair keyPair = loadKeyPairFromFile(); 
        HashMap<String, KeyPair>  keyPairMap = new HashMap<>();
        keyPairMap.put("key-id-0", keyPair);
        return keyPairMap;
    }
    
    /**
     * Exposes a PasswordEncode bean which will be used for one-way encoding
     * passwords. This will make sure passwords are not stored in plain text,
     * but as a hash, which will be compared to the hashed, entered user password
     * during authentication. This is what Facebook missed... ;)
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
    
    private KeyPair loadKeyPairFromFile() {
        
        // The keystore was created like this:
        //      keytool -genkey -alias jwtKeys -keyalg RSA -sigalg SHA256withRSA -keysize 2048 -validity 3650 -keypass password -keystore jwtKeys.jks -storepass password
        // followed by: 
        //      keytool -importkeystore -srckeystore jwtKeys.jks -destkeystore jwtKeys.jks -deststoretype pkcs12
        // See: http://javaevangelist.blogspot.com/2016/08/how-to-generate-sha-2-sha-256-self.html
        
        // See: https://www.baeldung.com/spring-security-oauth-jwt
        // See: http://blog.marcosbarbero.com/centralized-authorization-jwt-spring-boot2/
        // See: https://gist.github.com/ygotthilf/baa58da5c3dd1f69fae9
        // See: http://www.java2s.com/Code/Java/Security/RetrievingaKeyPairfromaKeyStore.htm
        
        KeyStoreKeyFactory keyStoreKeyFactory = 
          new KeyStoreKeyFactory(new ClassPathResource("jwtKeys.jks"), "password".toCharArray());
        return keyStoreKeyFactory.getKeyPair("jwtKeys");
    }
    
    /**
     * Programmatically generates a Key Pair at startup.
     * Note, this may require 3rd party libraries like BouncyCastle
     * for specific generation algorithms.
     * @return the generated key pair.
     * @throws NoSuchAlgorithmException 
     */
    @SuppressWarnings("unused")
    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        listSignatureAlgorithms();      
        listSecureRandomAlgorithms();
        
        // See: https://docs.oracle.com/javase/tutorial/security/apisign/step2.html
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = SecureRandom.getInstanceStrong();
        keyGen.initialize(2048, random);
        return keyGen.generateKeyPair();
    }
    
    private void listSecurityAlgorithms(String type) {
        TreeSet<String> algorithms = new TreeSet<>();
        for (Provider provider : Security.getProviders())
            for (Service service : provider.getServices())
                if (service.getType().equals(type))
                    algorithms.add(service.getAlgorithm());

        for (String algorithm : algorithms)
            System.out.println(algorithm);
    }

    private void listSignatureAlgorithms() {
        System.out.println("Available Signature Algorithms:");
        listSecurityAlgorithms("Signature");
    }

    private void listSecureRandomAlgorithms() {
        System.out.println("Available Secure Random Algorithms:");
        listSecurityAlgorithms("SecureRandom");
    }
}
