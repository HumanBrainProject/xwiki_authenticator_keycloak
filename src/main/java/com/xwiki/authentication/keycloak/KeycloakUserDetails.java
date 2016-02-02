/*
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

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
