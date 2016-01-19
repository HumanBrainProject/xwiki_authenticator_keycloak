package com.xwiki.authentication.keycloak;

import org.keycloak.representations.IDToken;

import java.io.Serializable;

/**
 * Created by timbo on 18/01/16.
 */
public class KeycloakUserDetails implements Serializable {

    private final String username;
    private final IDToken idToken;
    private final String realm;


    public KeycloakUserDetails(String username, IDToken idToken, String realm) {
        this.username = username;
        this.idToken = idToken;
        this.realm = realm;

    }

    public String getUsername() {
        return username;
    }

    public IDToken getIdToken() {
        return idToken;
    }

    public String getRealm() {
        return realm;
    }

}
