Provides XWiki authentication using Keycloak.

WARNING - this is work in progress and not yet functional

# Build

Add this to your ~/.m2/settings.xml file

<profile>
      <id>xwiki</id>
      <repositories>
        <repository>
          <id>xwiki-snapshots</id>
          <name>XWiki Nexus Snapshot Repository Proxy</name>
          <url>http://nexus.xwiki.org/nexus/content/groups/public-snapshots</url>
          <releases>
            <enabled>false</enabled>
          </releases>
          <snapshots>
            <enabled>true</enabled>
          </snapshots>
        </repository>
        <repository>
          <id>xwiki-releases</id>
          <name>XWiki Nexus Releases Repository Proxy</name>
          <url>http://nexus.xwiki.org/nexus/content/groups/public</url>
          <releases>
            <enabled>true</enabled>
          </releases>
          <snapshots>
            <enabled>false</enabled>
          </snapshots>
        </repository>
      </repositories>
      <pluginRepositories>
        <pluginRepository>
          <id>xwiki-plugins-snapshots</id>
          <name>XWiki Nexus Plugin Snapshot Repository Proxy</name>
          <url>http://nexus.xwiki.org/nexus/content/groups/public-snapshots</url>
          <releases>
            <enabled>false</enabled>
          </releases>
          <snapshots>
            <enabled>true</enabled>
          </snapshots>
        </pluginRepository>
        <pluginRepository>
          <id>xwiki-plugins-releases</id>
          <name>XWiki Nexus Plugin Releases Repository Proxy</name>
          <url>http://nexus.xwiki.org/nexus/content/groups/public</url>
          <releases>
            <enabled>true</enabled>
          </releases>
          <snapshots>
            <enabled>false</enabled>
          </snapshots>
        </pluginRepository>
      </pluginRepositories>
    </profile>


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
