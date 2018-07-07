/*
 * Copyright 2018 OmniFaces.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.omnifaces.jaccprovidertomee;

import java.security.Principal;
import org.apache.openejb.core.security.AbstractSecurityService.Group;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.jacc.PolicyContextException;
import javax.security.jacc.PolicyContextHandler;
import javax.servlet.http.HttpServletRequest;
import org.apache.catalina.connector.Request;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.users.AbstractRole;
import org.apache.catalina.users.AbstractUser;

/**
 * PolicyContextHandler that handles the following keys missing on TomEE:
 * <ul>
 * <li>javax.security.auth.Subject.container</li>
 * <li>javax.servlet.http.HttpServletRequest</li>
 * </ul>
 * @author Guillermo González de Agüero
 */
public class ServletPolicyContextHandler implements PolicyContextHandler {

    private static final String KEY_SUBJECT = "javax.security.auth.Subject.container";
    private static final String KEY_REQUEST = "javax.servlet.http.HttpServletRequest";
    public static final Set<String> KEYS = new HashSet<>(Arrays.asList(KEY_SUBJECT, KEY_REQUEST));

    private static final ThreadLocal<Request> CURRENT_REQUEST = new ThreadLocal<>();
    
    private static final ServletPolicyContextHandler INSTANCE = new ServletPolicyContextHandler();

    private ServletPolicyContextHandler() {
    }
    
    public static ServletPolicyContextHandler getInstance() {
        return INSTANCE;
    }

    public static void startRequest(Request request) {
        CURRENT_REQUEST.set(request);
    }

    public static void completeRequest() {
        CURRENT_REQUEST.remove();
    }

    @Override
    public boolean supports(String key) throws PolicyContextException {
        return KEYS.contains(key);
    }

    @Override
    public String[] getKeys() throws PolicyContextException {
        return KEYS.toArray(new String[]{});
    }

    @Override
    public Object getContext(String key, Object data) throws PolicyContextException {
        switch (key) {
            case KEY_SUBJECT:
                return getSubject();
            case KEY_REQUEST:
                return getServletRequest();
            default:
                throw new PolicyContextException("Invalid key: " + key);
        }
    }

    private Subject getSubject() {
        Request request = CURRENT_REQUEST.get();

        if (request == null || request.getPrincipal() == null) {
            return null;
        }

        Set<Principal> principals = new HashSet<>();
        
        Principal userPrincipal = request.getPrincipal();
        principals.add(request.getPrincipal());
        
        
        Group groups = new Group("Roles");
        if (userPrincipal instanceof AbstractUser) {
            Iterator<?> it = ((AbstractUser) userPrincipal).getRoles();

            while (it.hasNext()) {
                AbstractRole role = ((AbstractRole) it.next());
                groups.addMember(role);
            }
        } else if (userPrincipal instanceof GenericPrincipal) {
            String[] roles = ((GenericPrincipal) userPrincipal).getRoles();
            for (final String role : roles) {
                groups.addMember(() -> role);
            }
        }
        
        principals.add(groups);

        return new Subject(false, principals, Collections.emptySet(), Collections.emptySet());
    }

    private HttpServletRequest getServletRequest() {
        Request request = CURRENT_REQUEST.get();

        return request != null ? request : null;
    }
}
