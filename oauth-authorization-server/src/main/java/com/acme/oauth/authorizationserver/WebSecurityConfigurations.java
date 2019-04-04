package com.acme.oauth.authorizationserver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * A WebSecurityConfiguration which declares a user login 
 * and a hard-coded inMemory user to authenticate.
 * 
 * The login page will be generated on the fly and be 
 * accessible by the /login endpoint.
 */
@Configuration
public class WebSecurityConfigurations extends WebSecurityConfigurerAdapter {
    
    /**
     * The one-way password encoder used to encode secrets.
     * The bean is defined in {@link AuthorizationServer}.
     */
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    public WebSecurityConfigurations(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
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
     // @formatter:on
                
    }
    
    /**
     * Expose a UserDetailsService implementation that will
     * be picked up by the WebSecurityConfigurerAdapter.
     * This will essentially define users that will be able
     * to login with Basic Auth via the '/login' endpoint provided
     * by this server.
     */
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
        
        // see : http://blog.marcosbarbero.com/centralized-authorization-jwt-spring-boot2/
    }
}
