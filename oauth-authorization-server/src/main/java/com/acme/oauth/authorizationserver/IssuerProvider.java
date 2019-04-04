package com.acme.oauth.authorizationserver;

import com.nimbusds.oauth2.sdk.id.Issuer;

/**
 * Interface implemented by a bean
 * to provide access to a (request scoped)
 * issuer.
 */
public interface IssuerProvider {

    Issuer getIssuer();
}
