package org.omnifaces.jaccprovider;
import static java.util.Arrays.asList;
import static java.util.Collections.list;
import static org.omnifaces.jaccprovider.TestPolicyConfigurationFactory.getCurrentPolicyConfiguration;
 
import java.security.CodeSource;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.Policy;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
 
public class TestPolicy extends Policy {
     
    private Policy previousPolicy = Policy.getPolicy();
     
    @Override
    public boolean implies(ProtectionDomain domain, Permission permission) {
             
        TestPolicyConfiguration policyConfiguration = getCurrentPolicyConfiguration();
        TestRoleMapper roleMapper = policyConfiguration.getRoleMapper();
     
        if (isExcluded(policyConfiguration.getExcludedPermissions(), permission)) {
            // Excluded permissions cannot be accessed by anyone
            return false;
        }
         
        if (isUnchecked(policyConfiguration.getUncheckedPermissions(), permission)) {
            // Unchecked permissions are free to be accessed by everyone
            return true;
        }
         
        List<Principal> currentUserPrincipals = asList(domain.getPrincipals());
         
        if (!roleMapper.isAnyAuthenticatedUserRoleMapped() && !currentUserPrincipals.isEmpty()) {
            // The "any authenticated user" role is not mapped, so available to anyone and the current
            // user is assumed to be authenticated (we assume that an unauthenticated user doesn't have any principals
            // whatever they are)
            if (hasAccessViaRole(policyConfiguration.getPerRolePermissions(), "**", permission)) {
                // Access is granted purely based on the user being authenticated (the actual roles, if any, the user has it not important)
                return true;
            }
        }
        
        Subject subject;
        try {
            subject = (Subject)PolicyContext.getContext("javax.security.auth.Subject.container");
        } catch (PolicyContextException ex) {
            throw new RuntimeException(ex);
        }
         
        if (hasAccessViaRoles(policyConfiguration.getPerRolePermissions(), roleMapper.getMappedRoles(currentUserPrincipals, subject), permission)) {
            // Access is granted via role. Note that if this returns false it doesn't mean the permission is not
            // granted. A role can only grant, not take away permissions.
            return true;
        }
         
        // Access not granted via any of the JACC maintained Permissions. Check the previous (default) policy.
        // Note: this is likely to be called in case it concerns a Java SE type permissions.
        // TODO: Should we not distinguish between JACC and Java SE Permissions at the start of this method? Seems
        //       very unlikely that JACC would ever say anything about a Java SE Permission, or that the Java SE
        //       policy says anything about a JACC Permission. Why are these two systems even combined in the first place?
        if (previousPolicy != null) {
            return previousPolicy.implies(domain, permission);
        }
         
        return false;
    }
 
    @Override
    public PermissionCollection getPermissions(ProtectionDomain domain) {
 
        Permissions permissions = new Permissions();
         
        TestPolicyConfiguration policyConfiguration = getCurrentPolicyConfiguration();
        TestRoleMapper roleMapper = policyConfiguration.getRoleMapper();
         
        Permissions excludedPermissions = policyConfiguration.getExcludedPermissions();
 
        // First get all permissions from the previous (original) policy
        if (previousPolicy != null) {
            collectPermissions(previousPolicy.getPermissions(domain), permissions, excludedPermissions);
        }
 
        // If there are any static permissions, add those next
        if (domain.getPermissions() != null) {
            collectPermissions(domain.getPermissions(), permissions, excludedPermissions);
        }
 
        // Thirdly, get all unchecked permissions
        collectPermissions(policyConfiguration.getUncheckedPermissions(), permissions, excludedPermissions);
 
        
        Subject subject;
        try {
            subject = (Subject)PolicyContext.getContext("javax.security.auth.Subject.container");
        } catch (PolicyContextException ex) {
            throw new RuntimeException(ex);
        }
        
        // Finally get the permissions for each role *that the current user has*
        //
        // Note that the principles that are put into the ProtectionDomain object are those from the current user.
        // (for a Server application, passing in a Subject would have been more logical, but the Policy class was
        // made for Java SE with code-level security in mind). The Subject needs to be passed anyway as some servers
        // (namely WebSphere Liberty/OpenLiberty) are only accesible from the Subject
        Map<String, Permissions> perRolePermissions = policyConfiguration.getPerRolePermissions();
        for (String role : roleMapper.getMappedRoles(domain.getPrincipals(), subject)) {
            if (perRolePermissions.containsKey(role)) {
                collectPermissions(perRolePermissions.get(role), permissions, excludedPermissions);
            }
        }
 
        return permissions;
    }
     
    @Override
    public PermissionCollection getPermissions(CodeSource codesource) {
 
        Permissions permissions = new Permissions();
         
        TestPolicyConfigurationPermissions policyConfiguration = getCurrentPolicyConfiguration();
        Permissions excludedPermissions = policyConfiguration.getExcludedPermissions();
 
        // First get all permissions from the previous (original) policy
        if (previousPolicy != null) {
            collectPermissions(previousPolicy.getPermissions(codesource), permissions, excludedPermissions);
        }
 
        // Secondly get the static permissions. Note that there are only two sources possible here, without
        // knowing the roles of the current user we can't check the per role permissions.
        collectPermissions(policyConfiguration.getUncheckedPermissions(), permissions, excludedPermissions);
 
        return permissions;
    }
     
    private boolean isExcluded(Permissions excludedPermissions, Permission permission) {
        if (excludedPermissions.implies(permission)) {
            return true;
        }
         
        for (Permission excludedPermission : list(excludedPermissions.elements())) {
            if (permission.implies(excludedPermission)) {
                return true;
            }
        }
         
        return false;
    }
     
    private boolean isUnchecked(Permissions uncheckedPermissions, Permission permission) {
        return uncheckedPermissions.implies(permission);
    }
     
    private boolean hasAccessViaRoles(Map<String, Permissions> perRolePermissions, List<String> roles, Permission permission) {
        for (String role : roles) {
            if (hasAccessViaRole(perRolePermissions, role, permission)) {
                return true;
            }
        }
         
        return false;
    }
     
    private boolean hasAccessViaRole(Map<String, Permissions> perRolePermissions, String role, Permission permission) {
        return perRolePermissions.containsKey(role) && perRolePermissions.get(role).implies(permission);
    }
     
    /**
     * Copies permissions from a source into a target skipping any permission that's excluded.
     * 
     * @param sourcePermissions
     * @param targetPermissions
     * @param excludedPermissions
     */
    private void collectPermissions(PermissionCollection sourcePermissions, PermissionCollection targetPermissions, Permissions excludedPermissions) {
         
        boolean hasExcludedPermissions = excludedPermissions.elements().hasMoreElements();
         
        for (Permission permission : list(sourcePermissions.elements())) {
            if (!hasExcludedPermissions || !isExcluded(excludedPermissions, permission)) {
                targetPermissions.add(permission);
            }
        }
    }
     
}