Provides XWiki authentication using Keycloak.

WARNING - this is work in progress and not yet functional

# This authenticator execute the following process

 1. TODO

# Configuration

## xwiki.cfg file

TODO

# Install

* copy this authenticator jar file into WEB_INF/lib/
* setup xwiki.cfg with: xwiki.authentication.authclass=com.xwiki.authentication.keycloak.XWikiKeycloakAuthenticator

# Troubleshoot

## Debug log

    <!-- Header authenticator debugging -->
    <logger name="com.xwiki.authentication.keycloak.XWikiKeycloakAuthenticator" level="debug"/>

See http://platform.xwiki.org/xwiki/bin/view/AdminGuide/Logging for general information about logging in XWiki.
