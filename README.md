Provides XWiki authentication using Keycloak, a JBoss project that provides Single Sign On (SSO) using OpenID Connect
(as well as lots more).

NOTE: this authenticator is currently incomplete. The basic parts are working, but more work is needed.

# Build

This is a Maven project, in-line with other XWiki modules.
The assumption is that you are using it with Tomcat, but other containers should also work with minimal adaptation.

Add this to your ~/.m2/settings.xml file

``` xml
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
```

See [here](http://dev.xwiki.org/xwiki/bin/view/Community/Building) for more details on building XWiki parts.

Then run maven with this profile. 

``` sh 
mvn -Pxwiki package
```

This will build a jar file containing the authenticator in the target dir.

## Authentication process

1. The Keycloak Tomcat adapter is configured. This is a Tomcat Valve, which means it is installed at the Tomcat server level
e.g. in the $TOMCAT_HOME/lib dir.
1. Certain resources in XWiki are defined to be secured. Potentially you could secure everything, but at the very least
/bin/login/* should be secured so that any attempt in XWiki to login is intercepted by Tomcat and send to Keycloak.
 
When an unsecured page (that is unsecured at the Tomcat level) is accessed the following happens:
 
1. The request is passed on to XWiki.
1. XWiki decides if that page is accessible without logging in:
1. If so the page is returned
1. If not then the user is asked to log in by redirecting to something under /bin/login
1. As this page is secured by Tomcat then Keycloak authentication takes place and then the user is redirected back to 
the XWiki login process, and the authenticator is invoked (see next section)
1. The authenticator authenticates the user.
1. XWiki decides if that user should be allowed access to the page based on the group membership and access rights.
 
When a secured resource is accessed the following happens:
 
1. Keycloak adapter intercepts the request and redirects to Keycloak for authentication.
1. If the user is not yet logged in then Keycloak does this (e.g. prompting for username + password) and the Keycloak token
(extension of JSON Web Token used by the OpenID Connect protocol) is added to the headers.
1. If the user is already authenticated the Keycloak token is added to the headers.
1. Assuming successful authentication, Keycloak redirect back to the page that the user requested.
1. The Keycloak adapter recognises that the user is authenticated and passes on the request to XWiki
1. The XWiki Keycloak authenticator grabs the information from the Keycloak token, and looks for that user in XWiki
1. The if the user for that username does not exist then it is created (in XWiki a user is a wiki page).
1. The details (first name, last name, email etc.) from the Keycloak token are used to update the user's details in XWiki
(in case they have been updated since being created).
1. The XWiki groups that the user belong to (Keycloak roles) are updated (in case they have been updated since being created).
1. The username of the authenticated use is added to the session
1. The authenticated user is finally passed on to XWiki and the page is returned to the user. 

After authentication, if the user requests a page that is secured by XWiki but not by Tomcat then:

1. The XWiki Keycloak authenticator looks for the Keycloak token, but this is not present as the page is not secured by
Tomcat.
1. So instead the authenticator looks in the session for the authenticated user and finds it.
1. The authenticator returns the authenticated user to XWiki and the page is returned to the user.

The above process means that the ONLY resource that MUST be secured at the Tomcat level is /bin/login/* as XWIki does
all the deciding as to whether an user can access a page (using the standard XWiki mechanisms). When a page is secured 
at the XWiki level the user is requested to log in and at this point Keycloak handles the authentication. After being 
authenticated Xwiki handles all the authorizaion.

Of course, you CAN secure more at the Tomcat level (even the whole wiki) if you wish.


# Configuration

## Keycloak

General info on Keycloak can be found [here](http://keycloak.jboss.org/).

In short you need to:

1. setup Keycloak
1. add a realm definition and add a client to that realm for the XWiki application
1. define whatever users and roles are needed

## Tomcat

Info on configuring the Keycloak Tomcat adapter can be found [here](http://keycloak.github.io/docs/userguide/keycloak-server/html/ch08.html#tomcat-adapter)

To set up tomcat to use container authentication using the Keycloak adapter valve you need to:

1. add the Keycloak adapter jar files to the $TOMCAT_HOME/lib dir (1)
1. create a keycloak.json file and add it to XWiki's WEB-INF dir
1. secure the appropriate XWiki resources (possibly just /bin/login/*) in XWiki's web.xml

(1) NOTE: there is a clash (2) between the Bouncy Castle classes (3) used by Keycloak and XWiki which prevents things working 
"out of the box". You must remove the 2 offending classes from the Keycloak jars and replace with those from XWiki
(this was the case for Keycloak 1.7 and XWiki 7.3 - the situation may be different for other versions).

(2) The clash is due to the fact that the Keycloak adapter is a Tomcat valve and so the jars must be put in $TOMCAT_HOME/lib
but those classes are then visible to all web apps, and so potentially clash with jars found in XWiki's WEB-INF/lib dir.

(3) bcpkix-jdk15on-<version>.jar and bcprov-jdk15on-<version>.jar

An example web.xml is present in the root dir of this project.

## XWiki

In short you need to:

1. configure xwiki.cfg to use the authenticator
1. add the authenticator jar file built by this project to XWiki's WEB-INF/lib dir

### xwiki.cfg file

Various options can be defined here. The critical one is to tell XWiki to use our authenticator: 
`xwiki.authentication.authclass=com.xwiki.authentication.keycloak.XWikiKeycloakAuthenticator`

An example xwiki.cfg is present in the root dir of this project.

## Docker

A complete configuration using Docker can be found [here](https://github.com/InformaticsMatters/xwiki_keycloak_sso). 
This is the best place to look for all the specific details and the easiest place to get started.

# Troubleshoot

## Debug log

To change the logging level of the authenticator add this to WEB-INF/classes/logback.xml

    `<logger name="com.xwiki.authentication.keycloak.XWikiKeycloakAuthenticator" level="debug"/>`

See http://platform.xwiki.org/xwiki/bin/view/AdminGuide/Logging for general information about logging in XWiki.

To change the logging level of the Keycloak adapter add this to $TOMCAT_HOME/conf/logging.properties:

`org.keycloak.adapters.OAuthRequestAuthenticator.level = FINE`
