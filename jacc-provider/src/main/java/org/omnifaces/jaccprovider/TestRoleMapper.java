package org.omnifaces.jaccprovider;
import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.list;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.security.Principal;
import java.security.acl.Group;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.security.auth.Subject;

public class TestRoleMapper {

    private static Object geronimoPolicyConfigurationFactoryInstance;
    private static ConcurrentMap<String, Map<Principal, Set<String>>> geronimoContextToRoleMapping;

    private Map<String, List<String>> groupToRoles = new HashMap<>();

    private boolean oneToOneMapping;
    private boolean anyAuthenticatedUserRoleMapped = false;

    public static void onFactoryCreated() {
        tryInitGeronimo();
    }

    private static void tryInitGeronimo() {
        try {
            // Geronimo 3.0.1 contains a protection mechanism to ensure only a Geronimo policy provider is installed.
            // This protection can be beat by creating an instance of GeronimoPolicyConfigurationFactory once. This instance
            // will statically register itself with an internal Geronimo class
            geronimoPolicyConfigurationFactoryInstance = Class.forName("org.apache.geronimo.security.jacc.mappingprovider.GeronimoPolicyConfigurationFactory").newInstance();
            geronimoContextToRoleMapping = new ConcurrentHashMap<>();
        } catch (Exception e) {
            // ignore
        }
    }

    public static void onPolicyConfigurationCreated(final String contextID) {

        // Are we dealing with Geronimo?
        if (geronimoPolicyConfigurationFactoryInstance != null) {

            // PrincipalRoleConfiguration

            try {
                Class<?> geronimoPolicyConfigurationClass = Class.forName("org.apache.geronimo.security.jacc.mappingprovider.GeronimoPolicyConfiguration");

                Object geronimoPolicyConfigurationProxy = Proxy.newProxyInstance(TestRoleMapper.class.getClassLoader(), new Class[] {geronimoPolicyConfigurationClass}, new InvocationHandler() {

                    @SuppressWarnings("unchecked")
                    @Override
                    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {

                        // Take special action on the following method:

                        // void setPrincipalRoleMapping(Map<Principal, Set<String>> principalRoleMap) throws PolicyContextException;
                        if (method.getName().equals("setPrincipalRoleMapping")) {

                            geronimoContextToRoleMapping.put(contextID, (Map<Principal, Set<String>>) args[0]);

                        }
                        return null;
                    }
                });

                // Set the proxy on the GeronimoPolicyConfigurationFactory so it will call us back later with the role mapping via the following method:

                // public void setPolicyConfiguration(String contextID, GeronimoPolicyConfiguration configuration) {
                Class.forName("org.apache.geronimo.security.jacc.mappingprovider.GeronimoPolicyConfigurationFactory")
                     .getMethod("setPolicyConfiguration", String.class, geronimoPolicyConfigurationClass)
                     .invoke(geronimoPolicyConfigurationFactoryInstance, contextID, geronimoPolicyConfigurationProxy);


            } catch (ClassNotFoundException | NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
                // Ignore
            }
        }
    }


    public TestRoleMapper(String contextID, Collection<String> allDeclaredRoles) {
        // Initialize the groupToRoles map

        // Try to get a hold of the proprietary role mapper of each known
        // AS. Sad that this is needed :(
        if (tryGlassFish(contextID, allDeclaredRoles)) {
            return;
        } else if (tryWebLogic(contextID, allDeclaredRoles)) {
            return;
        } else if (tryGeronimo(contextID, allDeclaredRoles)) {
            return;
        } else {
            oneToOneMapping = true;
        }
    }

    public List<String> getMappedRoles(Principal[] principals, Subject subject) {
        return getMappedRoles(asList(principals), subject);
    }

    public boolean isAnyAuthenticatedUserRoleMapped() {
        return anyAuthenticatedUserRoleMapped;
    }

    /**
     * Tries to get the roles from the principals list and only if it fails,
     * falls back to looking at the Subject.
     *
     * Liberty is the only known server that falls back.
     *
     * @param principals the primary entities to look in for roles
     * @param subject the fall back to use if looking at principals fails
     * @return a list of mapped roles
     */
    public List<String> getMappedRoles(Iterable<Principal> principals, Subject subject) {

        // Extract the list of groups from the principals. These principals typically contain
        // different kind of principals, some groups, some others. The groups are unfortunately vendor
        // specific.
        List<String> groups = getGroups(principals, subject);

        // Map the groups to roles. E.g. map "admin" to "administrator". Some servers require this.
        return mapGroupsToRoles(groups);
    }

    private List<String> mapGroupsToRoles(List<String> groups) {

        if (oneToOneMapping) {
            // There is no mapping used, groups directly represent roles.
            return groups;
        }

        List<String> roles = new ArrayList<>();

        for (String group : groups) {
            if (groupToRoles.containsKey(group)) {
                roles.addAll(groupToRoles.get(group));
            } else {
                // Default to 1:1 mapping when group is not explicitly mapped
                roles.add(group);
            }
        }

        return roles;
    }

    private boolean tryGlassFish(String contextID, Collection<String> allDeclaredRoles) {

        try {
            Class<?> SecurityRoleMapperFactoryClass = Class.forName("org.glassfish.deployment.common.SecurityRoleMapperFactory");

            Object factoryInstance = Class.forName("org.glassfish.internal.api.Globals")
                                          .getMethod("get", SecurityRoleMapperFactoryClass.getClass())
                                          .invoke(null, SecurityRoleMapperFactoryClass);

            Object securityRoleMapperInstance = SecurityRoleMapperFactoryClass.getMethod("getRoleMapper", String.class)
                                                                              .invoke(factoryInstance, contextID);

            @SuppressWarnings("unchecked")
            Map<String, Subject> roleToSubjectMap = (Map<String, Subject>) Class.forName("org.glassfish.deployment.common.SecurityRoleMapper")
                                                                                .getMethod("getRoleToSubjectMapping")
                                                                                .invoke(securityRoleMapperInstance);

            for (String role : allDeclaredRoles) {
                if (roleToSubjectMap.containsKey(role)) {
                    Set<Principal> principals = roleToSubjectMap.get(role).getPrincipals();

                    List<String> groups = getGroups(principals, null);
                    for (String group : groups) {
                        if (!groupToRoles.containsKey(group)) {
                            groupToRoles.put(group, new ArrayList<String>());
                        }
                        groupToRoles.get(group).add(role);
                    }

                    if ("**".equals(role) && !groups.isEmpty()) {
                        // JACC spec 3.2 states:
                        //
                        // "For the any "authenticated user role", "**", and unless an application specific mapping has
                        // been established for this role,
                        // the provider must ensure that all permissions added to the role are granted to any
                        // authenticated user."
                        //
                        // Here we check for the "unless" part mentioned above. If we're dealing with the "**" role here
                        // and groups is not
                        // empty, then there's an application specific mapping and "**" maps only to those groups, not
                        // to any authenticated user.
                        anyAuthenticatedUserRoleMapped = true;
                    }
                }
            }

            return true;

        } catch (ClassNotFoundException | NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException
                | InvocationTargetException e) {
            return false;
        }
    }

    private boolean tryWebLogic(String contextID, Collection<String> allDeclaredRoles) {

        try {

            // See http://docs.oracle.com/cd/E21764_01/apirefs.1111/e13941/weblogic/security/jacc/RoleMapperFactory.html
            Class<?> roleMapperFactoryClass = Class.forName("weblogic.security.jacc.RoleMapperFactory");

            // RoleMapperFactory implementation class always seems to be the value of what is passed on the commandline
            // via the -Dweblogic.security.jacc.RoleMapperFactory.provider option.
            // See http://docs.oracle.com/cd/E57014_01/wls/SCPRG/server_prot.htm
            Object roleMapperFactoryInstance = roleMapperFactoryClass.getMethod("getRoleMapperFactory")
                                                                     .invoke(null);

            // See http://docs.oracle.com/cd/E21764_01/apirefs.1111/e13941/weblogic/security/jacc/RoleMapperFactory.html#getRoleMapperForContextID(java.lang.String)
            Object roleMapperInstance = roleMapperFactoryClass.getMethod("getRoleMapperForContextID", String.class)
                                                              .invoke(roleMapperFactoryInstance, contextID);

            // This seems really awkward; the Map contains BOTH group names and user names, without ANY way to
            // distinguish between the two.
            // If a user now has a name that happens to be a role as well, we have an issue :X
            @SuppressWarnings("unchecked")
            Map<String, String[]> roleToPrincipalNamesMap = (Map<String, String[]>) Class.forName("weblogic.security.jacc.simpleprovider.RoleMapperImpl")
                                                                                         .getMethod("getRolesToPrincipalNames")
                                                                                         .invoke(roleMapperInstance);

            for (String role : allDeclaredRoles) {
                if (roleToPrincipalNamesMap.containsKey(role)) {

                    List<String> groupsOrUserNames = asList(roleToPrincipalNamesMap.get(role));

                    for (String groupOrUserName : roleToPrincipalNamesMap.get(role)) {
                        // Ignore the fact that the collection also contains user names and hope
                        // that there are no user names in the application with the same name as a group
                        if (!groupToRoles.containsKey(groupOrUserName)) {
                            groupToRoles.put(groupOrUserName, new ArrayList<String>());
                        }
                        groupToRoles.get(groupOrUserName).add(role);
                    }

                    if ("**".equals(role) && !groupsOrUserNames.isEmpty()) {
                        // JACC spec 3.2 states: [...]
                        anyAuthenticatedUserRoleMapped = true;
                    }
                }
            }

            return true;

        } catch (ClassNotFoundException | NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException
                | InvocationTargetException e) {
            return false;
        }
    }

    private boolean tryGeronimo(String contextID, Collection<String> allDeclaredRoles) {
        if (geronimoContextToRoleMapping != null) {

            if (geronimoContextToRoleMapping.containsKey(contextID)) {
                Map<Principal, Set<String>> principalsToRoles = geronimoContextToRoleMapping.get(contextID);

                for (Map.Entry<Principal, Set<String>> entry : principalsToRoles.entrySet()) {

                    // Convert the principal that's used as the key in the Map to a list of zero or more groups.
                    // (for Geronimo we know that using the default role mapper it's always zero or one group)
                    for (String group : principalToGroups(entry.getKey())) {
                        if (!groupToRoles.containsKey(group)) {
                            groupToRoles.put(group, new ArrayList<String>());
                        }
                        groupToRoles.get(group).addAll(entry.getValue());

                        if (entry.getValue().contains("**")) {
                            // JACC spec 3.2 states: [...]
                            anyAuthenticatedUserRoleMapped = true;
                        }
                    }
                }
            }

            return true;
        }

        return false;
    }

    /**
     * Extracts the groups from the vendor specific principals.
     *
     * @param principals the primary entities to look in for groups
     * @param subject the fall back to use for finding groups, may be null
     * @return a list of (non-mapped) groups
     */
    @SuppressWarnings("unchecked")
    public List<String> getGroups(Iterable<Principal> principals, Subject subject) {
        List<String> groups = new ArrayList<>();

        for (Principal principal : principals) {
            if (principalToGroups(principal, groups)) {
                // return value of true means we're done early. This can be used
                // when we know there's only 1 principal holding all the groups
                return groups;
            }
        }

        if (subject == null) {
            return groups;
        }

        @SuppressWarnings("rawtypes")
        Set<Hashtable> tables = subject.getPrivateCredentials(Hashtable.class);
        if (tables != null && !tables.isEmpty()) {
            @SuppressWarnings("rawtypes")
            Hashtable table = tables.iterator().next();

            groups = (List<String>) table.get("com.ibm.wsspi.security.cred.groups");

            return groups != null ? groups : emptyList();
        }

        return groups;
    }

    public List<String> principalToGroups(Principal principal) {
        List<String> groups = new ArrayList<>();
        principalToGroups(principal, groups);
        return groups;
    }

    public boolean principalToGroups(Principal principal, List<String> groups) {
        switch (principal.getClass().getName()) {

            case "org.glassfish.security.common.Group": // GlassFish & Payara
            case "org.apache.geronimo.security.realm.providers.GeronimoGroupPrincipal": // Geronimo
            case "weblogic.security.principal.WLSGroupImpl": // WebLogic
            case "jeus.security.resource.GroupPrincipalImpl": // JEUS
                groups.add(principal.getName());
                break;

            case "org.jboss.security.SimpleGroup": // JBoss
                if (principal.getName().equals("Roles") && principal instanceof Group) {
                    Group rolesGroup = (Group) principal;
                    for (Principal groupPrincipal : list(rolesGroup.members())) {
                        groups.add(groupPrincipal.getName());
                    }

                    // Should only be one group holding the roles, so can exit the loop
                    // early
                    return true;
                }
            }
        return false;
    }

}