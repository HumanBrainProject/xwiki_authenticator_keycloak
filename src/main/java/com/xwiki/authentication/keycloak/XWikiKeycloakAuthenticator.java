/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
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

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang.StringUtils;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.representations.IDToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.model.EntityType;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.EntityReferenceSerializer;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.classes.BaseClass;
import com.xpn.xwiki.user.api.XWikiUser;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthServiceImpl;
import com.xpn.xwiki.web.Utils;
import com.xpn.xwiki.web.XWikiRequest;

/**
 * Authentication based on Keycloak OpenID Connect protocol
 * <p/>
 * Assumptions:
 * <ol>
 * <li>The keycloak adapter is configured to authenticate the user (e.g at the Tomcat level) and the details of the
 * authenticated user are available from the HttpServletRequest</li>
 * <li>Keycloak is configured to provide the roles required by XWiki. e.g. if XWiki expects a user to be a member of
 * the group XWiki.Foo then a role of that name will be configure in Keycloak and (maybe) assigned to the user</li>
 * </ol>
 *
 * @version $Id: $
 */
public class XWikiKeycloakAuthenticator extends XWikiAuthServiceImpl {
    /**
     * Logging tool.
     */
    private static final Logger LOG = LoggerFactory.getLogger(XWikiKeycloakAuthenticator.class);

    //    // Configuration
//    private static final String CONFIG_PREFIX = "xwiki.authentication.keycloak.";//    private static final String CONFIG_ID_FIELD = CONFIG_PREFIX + "id_field";
//    private static final String CONFIG_AUTH_FIELD = CONFIG_PREFIX + "auth_field";//    private static final String CONFIG_SECRET_FIELD = CONFIG_PREFIX + "secret_field";
//    private static final String CONFIG_SECRET_VALUE = CONFIG_PREFIX + "secret_value";
//    private static final String CONFIG_GROUP_FIELD = CONFIG_PREFIX + "group_field";
//    private static final String CONFIG_GROUP_VALUE_SEPARATOR = CONFIG_PREFIX + "group_value_separator";
//    private static final String CONFIG_GROUPS_MAPPING = CONFIG_PREFIX + "groups_mapping";
//    private static final String CONFIG_FIELDS_MAPPING = CONFIG_PREFIX + "fields_mapping";
//
//    // Default values for configuration
//    private static final String DEFAULT_AUTH_FIELD = "remote_user";
//    private static final String DEFAULT_ID_FIELD = DEFAULT_AUTH_FIELD;
//    private static final String DEFAULT_GROUP_FIELD = "";
//    private static final String DEFAULT_FIELDS_MAPPING = "email=mail,first_name=givenname,last_name=sn";
//    private static final String DEFAULT_GROUPS_MAPPING = "";
//    private static final String DEFAULT_GROUP_VALUE_SEPARATOR = "\\|";

    // TODO - define all the groups
    // QUESTION - what groups are needed?
    // QUESTION - shouldn't these be retrieved from XWiki rather than hardcoded? If so then how?
    private static final String[] XWIKI_GROUPS = {
            "XWiki.XWikiAllGroup"
            , "XWiki.XWikiAdminGroup"
    };

    /**
     * Space where user are stored in the wiki.
     */
    private static final EntityReference USER_SPACE_REFERENCE = new EntityReference("XWiki", EntityType.SPACE);

    /**
     * Key to store the authenticated username in session.
     */
    private static final String USERNAME_SESSION_KEY = XWikiKeycloakAuthenticator.class.getName() + ".username";


    /**
     * Used to resolve username to document reference.
     */
    private DocumentReferenceResolver<String> defaultDocumentReferenceResolver = Utils.getComponent(
            DocumentReferenceResolver.TYPE_STRING);

    /**
     * Used to serialize document reference to username.
     */
    private EntityReferenceSerializer<String> compactWikiEntityReferenceSerializer = Utils.getComponent(
            EntityReferenceSerializer.TYPE_STRING, "compactwiki");

//    /**
//     * Cache of the field mapping.
//     */
//    private Map<String, String> fieldMappings;
//
//    /**
//     * Cache of the group mapping.
//     */
//    private Map<String, DocumentReference> groupMappings;

    /**
     * {@inheritDoc}
     *
     * @see com.xpn.xwiki.user.impl.xwiki.AppServerTrustedAuthServiceImpl#checkAuth(com.xpn.xwiki.XWikiContext)
     */
    @Override
    public XWikiUser checkAuth(XWikiContext xwikiContext) throws XWikiException {

        // if its a protected page (defined at the Tomcat level) then there will be a Keycloak token present
        LOG.debug("Starting keycloak based authentication.");
        KeycloakSecurityContext keycloakContext = getKeycloakSecurityContext(xwikiContext);
        if (keycloakContext != null) {
            IDToken idToken = keycloakContext.getIdToken();
            if (idToken != null) {
                LOG.debug("Found authenticated keycloak user");

                // create user if needed, synchronize user group and set user in session
                DocumentReference validUser = authenticateUser(xwikiContext, keycloakContext);

                String user = compactWikiEntityReferenceSerializer.serialize(validUser);
                LOG.debug("XWiki user [{}] authenticated.", user);
                return new XWikiUser(user);
            }
        }

        // user may have previously been authenticated but this time requested a non-authenticated page
        //  so we must look in the session for the user
        LOG.debug("Looking for user in session");
        String sessionUser = getUserInSession(xwikiContext);
        if (sessionUser != null) {
            LOG.debug("User [{}] found in session", sessionUser);
            DocumentReference userDocRef = defaultDocumentReferenceResolver.resolve(sessionUser, USER_SPACE_REFERENCE);
            String user = compactWikiEntityReferenceSerializer.serialize(userDocRef);
            return new XWikiUser(user);
        }

        // no trace of the user having been authenticated so we fall back
        LOG.debug("No user found, falling back.");
        cleanUserInSession(xwikiContext);
        return super.checkAuth(xwikiContext);
    }

    /**
     * {@inheritDoc}
     *
     * @see com.xpn.xwiki.user.impl.xwiki.AppServerTrustedAuthServiceImpl#checkAuth(java.lang.String, java.lang.String,
     * java.lang.String, com.xpn.xwiki.XWikiContext)
     */
    @Override
    public XWikiUser checkAuth(String username, String password, String rememberme, XWikiContext xwikiContext)
            throws XWikiException {
//        String auth = getHeader(getAuthFieldName(context), context);
//
//        if (StringUtils.isEmpty(auth)) {
//            return super.checkAuth(username, password, rememberme, context);
//        } else {
//            return checkAuth(context);
//        }

        if (getKeycloakSecurityContext(xwikiContext) == null) {
            return super.checkAuth(username, password, rememberme, xwikiContext);
        } else {
            return checkAuth(xwikiContext);
        }
    }

    /**
     * If current session is not yet associated to the current user, ensure user existence and synchronization.
     *
     * @param xwikiContext    the current XWiki context.
     * @param keycloakContext the current Keycloak context.
     * @return a reference to the authenticated user.
     * @throws XWikiException on error.
     */
    private DocumentReference authenticateUser(XWikiContext xwikiContext, KeycloakSecurityContext keycloakContext) throws XWikiException {
        // convert user to avoid . and @ in names, and remove case sensitivity.

        IDToken token = keycloakContext.getIdToken();

        LOG.info("NAME = " + token.getName());
        LOG.info("PREFERRED USERNAME = " + token.getPreferredUsername());
        LOG.info("SUBJECT = " + token.getSubject());

        // TODO - maybe allow this to be configured from xwiki.cfg?
        if ("superadmin".equals(token.getPreferredUsername())) {
            throw new IllegalStateException("logging in as superadmin is not permitted");
        }

        String validUserName = getValidUserName(token.getPreferredUsername());

        DocumentReference validUser = defaultDocumentReferenceResolver.resolve(validUserName, USER_SPACE_REFERENCE);

        // If user already the current session user, do not try to synchronize it.
        if (!validUserName.equals(getUserInSession(xwikiContext))) {
            cleanUserInSession(xwikiContext);
            LOG.debug("Synchronizing XWiki user [{}]", validUser);
            synchronizeUser(validUser, xwikiContext, keycloakContext);
            setUserInSession(validUserName, xwikiContext);
        }
        return validUser;
    }

    /**
     * Create the user, retrieving user attributes.
     *
     * @param user            the reference of the user document.
     * @param xwikiContext    the current XWiki context.
     * @param keycloakContext the current Keycloak context.
     * @throws XWikiException on error.
     */
    private void createUser(DocumentReference user, XWikiContext xwikiContext, KeycloakSecurityContext keycloakContext) throws XWikiException {
        LOG.debug("Creating new XWiki user [{}]", user);

        // create user
        Map<String, String> extended = getExtendedUserInfo(keycloakContext);

        if (xwikiContext.getWiki().createUser(user.getName(), extended, xwikiContext) != 1) {
            throw new XWikiException(XWikiException.MODULE_XWIKI_USER, XWikiException.ERROR_XWIKI_USER_CREATE,
                    String.format("Unable to create user [{0}]", user));
        }

        LOG.info("Authenticated user [{}] has been successfully created.", user);
    }

    /**
     * Find the keycloak context from the XWiki context
     *
     * @param xwikiContext
     * @return
     */
    private KeycloakSecurityContext getKeycloakSecurityContext(XWikiContext xwikiContext) {
        Principal principal = xwikiContext.getRequest().getUserPrincipal();
        if (principal != null && principal instanceof KeycloakPrincipal) {
            KeycloakPrincipal kp = (KeycloakPrincipal) principal;
            if (kp != null) {
                return kp.getKeycloakSecurityContext();
            }
        }
        LOG.debug("KeycloakSecurityContext could not be found");
        return null;
    }

    private Map<String, String> getExtendedUserInfo(KeycloakSecurityContext keycloakContext) {
        Map<String, String> extended = new HashMap<>();
        IDToken token = keycloakContext.getIdToken();
        if (token == null) {
            LOG.warn("No ID token present. User attributes cannot be filled");
        } else {
            // TODO - read the necessary attributes from the keycloak token and fill the extended map
            // QUESTION - what attributes are expected?


            extended.put("email", token.getEmail());
            extended.put("username", token.getPreferredUsername());
            extended.put("nickname", token.getNickName());
            extended.put("first_name", token.getGivenName());
            extended.put("last_name", token.getFamilyName());
            extended.put("active", "1");

        }
        return extended;
    }

    /**
     * Create the user if needed, and synchronize user in mapped groups.
     *
     * @param user            the reference of the user document.
     * @param xwikiContext    the current context.
     * @param keycloakContext the current Keycloak context.
     * @throws XWikiException on error.
     */
    private void synchronizeUser(DocumentReference user, XWikiContext xwikiContext, KeycloakSecurityContext keycloakContext) throws XWikiException {

        String database = xwikiContext.getWikiId();
        try {
            // Switch to main wiki to force users to be global users
            xwikiContext.setWikiId(user.getWikiReference().getName());

            // test if user already exists
            if (!xwikiContext.getWiki().exists(user, xwikiContext)) {
                createUser(user, xwikiContext, keycloakContext);
            } else {
                // TODO - maybe synchronize user when not created?
            }

            synchronizeGroups(user, xwikiContext);
        } finally {
            xwikiContext.setWikiId(database);
        }
    }

    /**
     * Synchronize the user in mapped groups.
     *
     * @param user    the reference of the user document.
     * @param context the current context.
     */
    private void synchronizeGroups(DocumentReference user, XWikiContext context) {
//        Map<String, DocumentReference> myGroupMappings = getGroupMapping(context);
//
//        // Only synchronize groups if a group mapping configuration exists
//        if (myGroupMappings.size() > 0) {
//            try {
//                String[] groups = getGroupFieldHeaderValue(context);
//                Collection<DocumentReference> groupInRefs = new ArrayList<DocumentReference>();
//                Collection<DocumentReference> groupOutRefs = new ArrayList<DocumentReference>();
//
//                // membership to add
//                if (groups != null) {
//                    for (String group : groups) {
//                        if (!group.trim().equals("")) {
//                            DocumentReference groupRef = myGroupMappings.get(group);
//                            if (groupRef == null) {
//                                LOG.warn("No mapping to XWiki group has been found for header group [{}].", group);
//                            } else {
//                                groupInRefs.add(groupRef);
//                            }
//                        }
//                    }
//                }
//
//                // membership to remove
//                for (DocumentReference groupRef : myGroupMappings.values()) {
//                    if (!groupInRefs.contains(groupRef)) {
//                        groupOutRefs.add(groupRef);
//                    }
//                }
//
//                // apply synch
//                syncGroupsMembership(user, groupInRefs, groupOutRefs, context);
//            } catch (Exception e) {
//                // we should continue although we have not been able to update the groups
//                // however we should log an error
//                LOG.error("Failed to update groups for user [{}]", user, e);
//            }
//        }

        Collection<DocumentReference> groupInRefs = new ArrayList<>();
        Collection<DocumentReference> groupOutRefs = new ArrayList<>();
        try {
            for (Map.Entry<String, DocumentReference> e : getXWikiGroups().entrySet()) {
                // we assume that we assign the exact roles needed by XWiki in Keycloak
//                if (context.getRequest().isUserInRole(e.getKey())) {
//                    groupInRefs.add(e.getValue());
//                } else {
//                    groupOutRefs.add(e.getValue());
//                }
                groupInRefs.add(e.getValue()); // give them everything for now
            }

            // apply synch
            syncGroupsMembership(user, groupInRefs, groupOutRefs, context);


        } catch (Exception e) {
            // we should continue although we have not been able to update the groups
            // however we should log an error
            LOG.error("Failed to update groups for user [{}]", user, e);
        }
    }

    /**
     * Get the XWiki groups that a user can belong to
     *
     * @return Map of DocumentReferences keyed by the group name
     */
    private Map<String, DocumentReference> getXWikiGroups() {
        Map<String, DocumentReference> map = new HashMap<>();
        for (String groupName : XWIKI_GROUPS) {
            LOG.debug("Getting DocumentReference for group [{}]", groupName);
            map.put(groupName, defaultDocumentReferenceResolver.resolve(groupName, USER_SPACE_REFERENCE));
        }
        return map;
    }

    /**
     * Return a normalized lowercase username. It replace dot sign by equal sign and at sign by underscore.
     *
     * @param userName the username to normalize.
     * @return a normalized name.
     */
    private String getValidUserName(String userName) {
        return userName.replace('.', '=').replace('@', '_').toLowerCase();
    }

    /**
     * @param context the current context.
     * @return the current servlet request, or null if none is available.
     */
    private static HttpServletRequest getServletRequest(XWikiContext context) {
        if (context == null) {
            return null;
        }

        XWikiRequest request = context.getRequest();
        if (request == null) {
            return null;
        }

        return request.getHttpServletRequest();
    }

    /**
     * @param context the current context.
     * @return the current session (create a new one if needed), or null if request is not available.
     */
    private static HttpSession getSession(XWikiContext context) {
        HttpServletRequest request = getServletRequest(context);
        if (request == null) {
            return null;
        }
        return request.getSession(true);
    }

//    /**
//     * @param name    the name of the header.
//     * @param context the current context.
//     * @return the value of the named request header, or null if no value is defined.
//     */
//    private static String getHeader(String name, XWikiContext context) {
//        if (StringUtils.isBlank(name)) {
//            return null;
//        }
//
//        HttpServletRequest request = getServletRequest(context);
//        if (request == null) {
//            return null;
//        }
//        return request.getHeader(name);
//    }

    /**
     * Set the given user in the session.
     *
     * @param user    the user name.
     * @param context the current context.
     */
    private static void setUserInSession(String user, XWikiContext context) {
        HttpSession session = getSession(context);
        if (session == null) {
            return;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("XWiki user [{}] associated to session [{}]", user, session.getId());
        }
        session.setAttribute(USERNAME_SESSION_KEY, user);
    }

    /**
     * Set the given user in the session.
     *
     * @param context the current context.
     */
    private static void cleanUserInSession(XWikiContext context) {
        HttpSession session = getSession(context);
        if (session == null) {
            return;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Clean XWiki user from session [{}]", session.getId());
        }
        session.removeAttribute(USERNAME_SESSION_KEY);
    }

    /**
     * @param context the current context.
     * @return the user in session, or null if the session is not associated with a user.
     */
    private static String getUserInSession(XWikiContext context) {
        HttpSession session = getSession(context);
        if (session == null) {
            return null;
        }
        String user = (String) session.getAttribute(USERNAME_SESSION_KEY);
        if (LOG.isDebugEnabled() && user != null) {
            LOG.debug("XWiki user [{}] retrieved from session [{}]", user, session.getId());
        }
        return user;
    }

//    /**
//     * @param context the current context.
//     * @return the name of the user id field.
//     */
//    private static String getIdFieldName(XWikiContext context)
//    {
//        return context.getWiki().Param(CONFIG_ID_FIELD, DEFAULT_ID_FIELD);
//    }
//
//    /**
//     * @param context the current context.
//     * @return the name of the user field.
//     */
//    private static String getAuthFieldName(XWikiContext context) {
//        return context.getWiki().Param(CONFIG_AUTH_FIELD, DEFAULT_AUTH_FIELD);
//    }
//
//    /**
//     * @param context the current context.
//     * @return the name of the shared secret field.
//     */
//    private static String getSecretFieldName(XWikiContext context)
//    {
//        return context.getWiki().Param(CONFIG_SECRET_FIELD, null);
//    }
//
//    /**
//     * @param context the current context.
//     * @return the expected shared secret value.
//     */
//    private static String getSecretFieldValue(XWikiContext context)
//    {
//        return context.getWiki().Param(CONFIG_SECRET_VALUE, null);
//    }
//
//    /**
//     * @param context the current context.
//     * @return the name of the group field.
//     */
//    private static String getGroupFieldName(XWikiContext context)
//    {
//        return context.getWiki().Param(CONFIG_GROUP_FIELD, DEFAULT_GROUP_FIELD);
//    }
//
//    /**
//     * @param context the current context.
//     * @return the separator to use to parse the group field.
//     */
//    private static String getGroupValueSeparator(XWikiContext context)
//    {
//        return context.getWiki().Param(CONFIG_GROUP_VALUE_SEPARATOR, DEFAULT_GROUP_VALUE_SEPARATOR);
//    }
//
//    /**
//     * @param context the current context.
//     * @return the list of group name extracted from the group field.
//     */
//    private static String[] getGroupFieldHeaderValue(XWikiContext context)
//    {
//        String headerValue = getHeader(getGroupFieldName(context), context);
//        if (StringUtils.isBlank(headerValue)) {
//            return null;
//        }
//
//        return headerValue.split(getGroupValueSeparator(context));
//    }
//
//    /**
//     * @param context the current context.
//     * @return the user information based on field mapping.
//     */
//    private Map<String, String> getExtendedInformations(XWikiContext context)
//    {
//        Map<String, String> extInfos = new HashMap<String, String>();
//
//        for (Map.Entry<String, String> entry : getFieldMapping(context).entrySet()) {
//            String headerValue = getHeader(entry.getValue(), context);
//
//            if (!StringUtils.isBlank(headerValue)) {
//                extInfos.put(entry.getKey(), headerValue.trim());
//            }
//        }
//
//        return extInfos;
//    }
//
//    /**
//     * @param context the XWiki context.
//     * @return the mapping between HTTP header fields names and XWiki user profile fields names.
//     */
//    private Map<String, String> getFieldMapping(XWikiContext context)
//    {
//        if (this.fieldMappings == null) {
//            this.fieldMappings =
//                getMappingsParameter(CONFIG_FIELDS_MAPPING, DEFAULT_FIELDS_MAPPING, context);
//        }
//
//        return this.fieldMappings;
//    }
//
//    /**
//     * @param context the XWiki context.
//     * @return the mapping between HTTP header group names and values read from keycloak.
//     */
//    private Map<String, DocumentReference> getGroupMapping(XWikiContext context)
//    {
//        if (this.groupMappings == null) {
//            Map<String, String> mappings = getMappingsParameter(CONFIG_GROUPS_MAPPING, DEFAULT_GROUPS_MAPPING, context);
//            this.groupMappings = new HashMap<String, DocumentReference>();
//            for (Map.Entry<String, String> mapping : mappings.entrySet()) {
//                this.groupMappings.put(mapping.getKey(),
//                    defaultDocumentReferenceResolver.resolve(mapping.getValue(), USER_SPACE_REFERENCE));
//            }
//        }
//
//        return this.groupMappings;
//    }
//
//    /**
//     * Get a mapping from configuration.
//     *
//     * @param param        the name of the configuration param to parse.
//     * @param defaultParam the default value if the configuration is missing.
//     * @param context      the current context.
//     * @return a mapping configuration.
//     */
//    private static Map<String, String> getMappingsParameter(String param, String defaultParam, XWikiContext context) {
//        Map<String, String> result = new HashMap<String, String>();
//        String mappings = context.getWiki().Param(param, defaultParam);
//
//        if (StringUtils.isBlank(mappings)) {
//            return result;
//        }
//
//        String[] parsedMappings = mappings.split(",");
//
//        for (String mapping : parsedMappings) {
//            String[] parsedMapping = mapping.split("=", 2);
//            if (parsedMapping.length > 1) {
//                result.put(parsedMapping[0].trim(), parsedMapping[1].trim());
//            } else {
//                LOG.error("Error parsing " + param + " in xwiki.cfg: " + mapping);
//            }
//        }
//
//        return result;
//    }

    private void syncGroupsMembership(DocumentReference user, Collection<DocumentReference> groupInRefs,
                                      Collection<DocumentReference> groupOutRefs, XWikiContext context) throws XWikiException {

        Collection<DocumentReference> xwikiUserGroupList =
                context.getWiki().getGroupService(context).getAllGroupsReferencesForMember(user, 0, 0, context);

        if (LOG.isDebugEnabled()) {
            LOG.debug("XWiki groups the user is supposed to be member: " + groupInRefs);
            LOG.debug("XWiki groups the user is supposed to be not member: " + groupOutRefs);
            LOG.debug("The user belongs to following XWiki groups: " + xwikiUserGroupList);
        }

        for (DocumentReference groupRef : groupInRefs) {
            if (!xwikiUserGroupList.contains(groupRef)) {
                addUserToXWikiGroup(user, groupRef, context);
            }
        }

        for (DocumentReference groupRef : groupOutRefs) {
            if (xwikiUserGroupList.contains(groupRef)) {
                removeUserFromXWikiGroup(user, groupRef, context);
            }
        }
    }

    /**
     * Remove user name from provided XWiki group.
     *
     * @param user    the user.
     * @param group   the name of the group.
     * @param context the XWiki context.
     */
    private void removeUserFromXWikiGroup(DocumentReference user, DocumentReference group, XWikiContext context) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Removing user [{}] from xwiki group [{}]", user, group);
        }

        try {
            BaseClass groupClass = context.getWiki().getGroupClass(context);
            String userName = compactWikiEntityReferenceSerializer.serialize(user);

            // Get the XWiki document holding the objects comprising the group membership list
            XWikiDocument groupDoc = context.getWiki().getDocument(group, context);

            if (groupDoc.isNew()) {
                throw new Exception("Group [" + group + "] does not exists");
            }

            synchronized (groupDoc) {
                // Get and remove the specific group membership object for the user
                BaseObject groupObj = groupDoc.getXObject(groupClass.getReference(), "member", userName);
                groupDoc.removeXObject(groupObj);

                // Save modifications
                context.getWiki().saveDocument(groupDoc, "Header authenticator group synchronization", context);
            }
        } catch (Exception e) {
            LOG.error("Failed to remove a user [{}] from a group [{}]", user, group, e);
        }
    }

    /**
     * Add user name to provided XWiki group.
     *
     * @param user    the user.
     * @param group   the name of the group.
     * @param context the XWiki context.
     */
    private void addUserToXWikiGroup(DocumentReference user, DocumentReference group, XWikiContext context) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Adding user [{}] to xwiki group [{}]", user, group);
        }

        try {
            BaseClass groupClass = context.getWiki().getGroupClass(context);
            String userName = compactWikiEntityReferenceSerializer.serialize(user);

            // Get document representing group
            XWikiDocument groupDoc = context.getWiki().getDocument(group, context);

            if (groupDoc.isNew()) {
                throw new Exception("Group [" + group + "] does not exists");
            }

            synchronized (groupDoc) {
                // Add a member object to document
                BaseObject memberObj = groupDoc.newXObject(groupClass.getReference(), context);
                memberObj.setStringValue("member", userName);

                // Save modifications
                context.getWiki().saveDocument(groupDoc, "Header authenticator group synchronization", context);
            }
        } catch (Exception e) {
            LOG.error("Failed to add a user [{}] to a group [{}]", user, group, e);
        }
    }

}
