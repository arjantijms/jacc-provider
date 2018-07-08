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
package org.omnifaces.jaccprovidertomee.org.apache.geronimo.web.security;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyContextException;
import javax.security.jacc.WebResourcePermission;
import javax.security.jacc.WebRoleRefPermission;
import javax.security.jacc.WebUserDataPermission;
import org.apache.catalina.Container;
import org.apache.catalina.Context;
import org.apache.catalina.Wrapper;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;

/**
 *
 * @author Guillermo González de Agüero
 */
public class SpecSecurityBuilder {

    private final Set<String> securityRoles = new HashSet<String>();

    private final Map<String, URLPattern> uncheckedPatterns = new HashMap<String, URLPattern>();

    private final Map<UncheckedItem, HTTPMethods> uncheckedResourcePatterns = new HashMap<UncheckedItem, HTTPMethods>();

    private final Map<UncheckedItem, HTTPMethods> uncheckedUserPatterns = new HashMap<UncheckedItem, HTTPMethods>();

    private final Map<String, URLPattern> excludedPatterns = new HashMap<String, URLPattern>();

    private final Map<String, Map<String, URLPattern>> rolesPatterns = new HashMap<String, Map<String, URLPattern>>();

    private final Set<URLPattern> allSet = new HashSet<URLPattern>();

    private final Map<String, URLPattern> allMap = new HashMap<String, URLPattern>(); //uncheckedPatterns union excludedPatterns union rolesPatterns.

    private final Context webAppInfo;
    private final PolicyConfiguration policyConfiguration;

    public SpecSecurityBuilder(Context webAppInfo, PolicyConfiguration policyConfiguration) {
        this.webAppInfo = webAppInfo;
        this.policyConfiguration = policyConfiguration;
    }

    public void buildSpecSecurityConfig() {
        securityRoles.addAll(Arrays.asList(webAppInfo.findSecurityRoles()));

        try {
            for (Container container : webAppInfo.findChildren()) {
                if (container instanceof Wrapper) {
                    // The element is a Servlet
                    processRoleRefPermissions((Wrapper) container);
                }
            }

            //add the role-ref permissions for unmapped jsps
            addUnmappedJSPPermissions();
            analyzeSecurityConstraints(Arrays.asList(webAppInfo.findConstraints()));
            removeExcludedDups();
            buildComponentPermissions();
        } catch (PolicyContextException e) {
            throw new IllegalStateException("Should not happen", e);
        }
    }

    private void analyzeSecurityConstraints(List<SecurityConstraint> securityConstraints) {
        for (SecurityConstraint securityConstraint : securityConstraints) {
            Map<String, URLPattern> currentPatterns = null;
            Set<String> roleNames = null;
            if (securityConstraint.getAuthConstraint()) {
                if (securityConstraint.findAuthRoles().length == 0) {
                    currentPatterns = excludedPatterns;
                } else {
                    roleNames = new HashSet<String>(Arrays.asList(securityConstraint.findAuthRoles()));
                    if (roleNames.remove("*")) {
                        roleNames.addAll(securityRoles);
                    }
                }
            } else {
                currentPatterns = uncheckedPatterns;
            }
            String transport = securityConstraint.getUserConstraint() == null ? "NONE" : securityConstraint.getUserConstraint();

            boolean isRolebasedPatten = (currentPatterns == null);

            if (securityConstraint.findCollections() != null) {
                for (SecurityCollection webResourceCollection : securityConstraint.findCollections()) {
                    //Calculate HTTP methods list
                    for (String urlPattern : webResourceCollection.findPatterns()) {
                        if (isRolebasedPatten) {
                            for (String roleName : roleNames) {
                                Map<String, URLPattern> currentRolePatterns = rolesPatterns.get(roleName);
                                if (currentRolePatterns == null) {
                                    currentRolePatterns = new HashMap<>();
                                    rolesPatterns.put(roleName, currentRolePatterns);
                                }

                                boolean omission = false;
                                String[] httpMethods = webResourceCollection.findMethods();
                                if (httpMethods.length == 0) {
                                    omission = true;
                                    httpMethods = webResourceCollection.findOmittedMethods();
                                }

                                analyzeURLPattern(urlPattern, new HashSet<>(Arrays.asList(httpMethods)), omission, transport, currentRolePatterns);
                            }
                        } else {
                            boolean omission = false;
                            String[] httpMethods = webResourceCollection.findMethods();
                            if (httpMethods.length == 0) {
                                omission = true;
                                httpMethods = webResourceCollection.findOmittedMethods();
                            }

                            analyzeURLPattern(urlPattern, new HashSet<>(Arrays.asList(httpMethods)), omission, transport, currentPatterns);
                        }
                        URLPattern allPattern = allMap.get(urlPattern);
                        if (allPattern == null) {
                            boolean omission = false;
                            String[] httpMethods = webResourceCollection.findMethods();
                            if (httpMethods.length == 0) {
                                omission = true;
                                httpMethods = webResourceCollection.findOmittedMethods();
                            }

                            allPattern = new URLPattern(urlPattern, new HashSet<>(Arrays.asList(httpMethods)), omission);
                            allSet.add(allPattern);
                            allMap.put(urlPattern, allPattern);
                        } else {
                            boolean omission = false;
                            String[] httpMethods = webResourceCollection.findMethods();
                            if (httpMethods.length == 0) {
                                omission = true;
                                httpMethods = webResourceCollection.findOmittedMethods();
                            }

                            allPattern.addMethods(new HashSet<>(Arrays.asList(httpMethods)), omission);
                        }

                    }
                }
            }
        }
    }

    private void analyzeURLPattern(String urlPattern, Set<String> httpMethods, boolean omission, String transport, Map<String, URLPattern> currentPatterns) {
        URLPattern pattern = currentPatterns.get(urlPattern);
        if (pattern == null) {
            pattern = new URLPattern(urlPattern, httpMethods, omission);
            currentPatterns.put(urlPattern, pattern);
        } else {
            pattern.addMethods(httpMethods, omission);
        }
        pattern.setTransport(transport);
    }

    private void removeExcludedDups() {
        for (Map.Entry<String, URLPattern> excluded : excludedPatterns.entrySet()) {
            String url = excluded.getKey();
            URLPattern pattern = excluded.getValue();
            removeExcluded(url, pattern, uncheckedPatterns);
            for (Map<String, URLPattern> rolePatterns : rolesPatterns.values()) {
                removeExcluded(url, pattern, rolePatterns);
            }
        }
    }

    private void removeExcluded(String url, URLPattern pattern, Map<String, URLPattern> patterns) {
        URLPattern testPattern = patterns.get(url);
        if (testPattern != null) {
            if (!testPattern.removeMethods(pattern)) {
                patterns.remove(url);
            }
        }
    }

    private void buildComponentPermissions() throws PolicyContextException {
        for (URLPattern pattern : excludedPatterns.values()) {
            String name = pattern.getQualifiedPattern(allSet);
            String actions = pattern.getMethods();
            policyConfiguration.addToExcludedPolicy(new WebResourcePermission(name, actions));
            policyConfiguration.addToExcludedPolicy(new WebUserDataPermission(name, actions));
        }
        for (Map.Entry<String, Map<String, URLPattern>> entry : rolesPatterns.entrySet()) {
            Set<URLPattern> currentRolePatterns = new HashSet<URLPattern>(entry.getValue().values());
            for (URLPattern pattern : entry.getValue().values()) {
                String name = pattern.getQualifiedPattern(currentRolePatterns);
                String actions = pattern.getMethods();
                WebResourcePermission permission = new WebResourcePermission(name, actions);
                policyConfiguration.addToRole(entry.getKey(), permission);
                HTTPMethods methods = pattern.getHTTPMethods();
                int transportType = pattern.getTransport();
                addOrUpdatePattern(uncheckedUserPatterns, name, methods, transportType);
            }
        }
        for (URLPattern pattern : uncheckedPatterns.values()) {
            String name = pattern.getQualifiedPattern(allSet);
            HTTPMethods methods = pattern.getHTTPMethods();
            addOrUpdatePattern(uncheckedResourcePatterns, name, methods, URLPattern.NA);
            int transportType = pattern.getTransport();
            addOrUpdatePattern(uncheckedUserPatterns, name, methods, transportType);
        }
        /**
         * A <code>WebResourcePermission</code> and a
         * <code>WebUserDataPermission</code> must be instantiated for each
         * <tt>url-pattern</tt> in the deployment descriptor and the default
         * pattern "/", that is not combined by the
         * <tt>web-resource-collection</tt> elements of the deployment
         * descriptor with ever HTTP method value. The permission objects must
         * be contructed using the qualified pattern as their name and with
         * actions defined by the subset of the HTTP methods that do not occur
         * in combination with the pattern. The resulting permissions that must
         * be added to the unchecked policy statements by calling the
         * <code>addToUncheckedPolcy</code> method on the
         * <code>PolicyConfiguration</code> object.
         */
        for (URLPattern pattern : allSet) {
            String name = pattern.getQualifiedPattern(allSet);
            HTTPMethods methods = pattern.getComplementedHTTPMethods();
            if (methods.isNone()) {
                continue;
            }
            addOrUpdatePattern(uncheckedResourcePatterns, name, methods, URLPattern.NA);
            addOrUpdatePattern(uncheckedUserPatterns, name, methods, URLPattern.NA);
        }
        if (!allMap.containsKey("/")) {
            URLPattern pattern = new URLPattern("/", Collections.<String>emptySet(), false);
            String name = pattern.getQualifiedPattern(allSet);
            HTTPMethods methods = pattern.getComplementedHTTPMethods();
            addOrUpdatePattern(uncheckedResourcePatterns, name, methods, URLPattern.NA);
            addOrUpdatePattern(uncheckedUserPatterns, name, methods, URLPattern.NA);
        }
        //Create the uncheckedPermissions for WebResourcePermissions
        for (UncheckedItem item : uncheckedResourcePatterns.keySet()) {
            HTTPMethods methods = uncheckedResourcePatterns.get(item);
            String actions = URLPattern.getMethodsWithTransport(methods, item.getTransportType());
            policyConfiguration.addToUncheckedPolicy(new WebResourcePermission(item.getName(), actions));
        }
        //Create the uncheckedPermissions for WebUserDataPermissions
        for (UncheckedItem item : uncheckedUserPatterns.keySet()) {
            HTTPMethods methods = uncheckedUserPatterns.get(item);
            String actions = URLPattern.getMethodsWithTransport(methods, item.getTransportType());
            policyConfiguration.addToUncheckedPolicy(new WebUserDataPermission(item.getName(), actions));
        }
    }

    private void addOrUpdatePattern(Map<UncheckedItem, HTTPMethods> patternMap, String name, HTTPMethods actions, int transportType) {
        UncheckedItem item = new UncheckedItem(name, transportType);
        HTTPMethods existingActions = patternMap.get(item);
        if (existingActions != null) {
            patternMap.put(item, existingActions.add(actions));
        } else {
            patternMap.put(item, new HTTPMethods(actions, false));
        }
    }

    protected void processRoleRefPermissions(Wrapper servlet) throws PolicyContextException {
        String servletName = servlet.getName();
        //WebRoleRefPermissions
        Set<String> unmappedRoles = new HashSet<>(securityRoles);
        for (String securityRoleRef : servlet.findSecurityReferences()) {
            //jacc 3.1.3.2
            /*   The name of the WebRoleRefPermission must be the servlet-name in whose
            * context the security-role-ref is defined. The actions of the  WebRoleRefPermission
            * must be the value of the role-name (that is the  reference), appearing in the security-role-ref.
            * The deployment tools must  call the addToRole method on the PolicyConfiguration object to add the
            * WebRoleRefPermission object resulting from the translation to the role
            * identified in the role-link appearing in the security-role-ref.
             */
            policyConfiguration.addToRole(servlet.findSecurityReference(securityRoleRef), new WebRoleRefPermission(servletName, securityRoleRef));
            unmappedRoles.remove(securityRoleRef);
        }
        for (String roleName : unmappedRoles) {
            policyConfiguration.addToRole(roleName, new WebRoleRefPermission(servletName, roleName));
        }
    }

    protected void addUnmappedJSPPermissions() throws PolicyContextException {
        for (String roleName : securityRoles) {
            policyConfiguration.addToRole(roleName, new WebRoleRefPermission("", roleName));
        }
    }

    public void clear() {
        securityRoles.clear();
        uncheckedPatterns.clear();
        uncheckedResourcePatterns.clear();
        uncheckedUserPatterns.clear();
        excludedPatterns.clear();
        rolesPatterns.clear();
        allSet.clear();
        allMap.clear();
    }
}
