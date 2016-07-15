package org.omnifaces.jaccprovider;
import java.security.Permission;
import java.security.Permissions;
import java.util.HashMap;
import java.util.Map;
 
import javax.security.jacc.PolicyContextException;
 
public abstract class TestPolicyConfigurationPermissions extends TestPolicyConfigurationBase {
 
    private Permissions excludedPermissions = new Permissions();
    private Permissions uncheckedPermissions = new Permissions();
    private Map<String, Permissions> perRolePermissions = new HashMap<String, Permissions>();
     
    public TestPolicyConfigurationPermissions(String contextID) {
        super(contextID);
    }
 
    @Override
    public void addToExcludedPolicy(Permission permission) throws PolicyContextException {
        excludedPermissions.add(permission);
    }
 
    @Override
    public void addToUncheckedPolicy(Permission permission) throws PolicyContextException {
        uncheckedPermissions.add(permission);
    }
 
    @Override
    public void addToRole(String roleName, Permission permission) throws PolicyContextException {
        Permissions permissions = perRolePermissions.get(roleName);
        if (permissions == null) {
            permissions = new Permissions();
            perRolePermissions.put(roleName, permissions);
        }
         
        permissions.add(permission);
    }
     
    @Override
    public void delete() throws PolicyContextException {
        removeExcludedPolicy();
        removeUncheckedPolicy();
        perRolePermissions.clear();
    }
 
    @Override
    public void removeExcludedPolicy() throws PolicyContextException {
        excludedPermissions = new Permissions();
    }
 
    @Override
    public void removeRole(String roleName) throws PolicyContextException {
        if (perRolePermissions.containsKey(roleName)) {
            perRolePermissions.remove(roleName);
        } else if ("*".equals(roleName)) {
            perRolePermissions.clear();
        }
    }
 
    @Override
    public void removeUncheckedPolicy() throws PolicyContextException {
        uncheckedPermissions = new Permissions();
    }
     
    public Permissions getExcludedPermissions() {
        return excludedPermissions;
    }
 
    public Permissions getUncheckedPermissions() {
        return uncheckedPermissions;
    }
 
    public Map<String, Permissions> getPerRolePermissions() {
        return perRolePermissions;
    }
 
}