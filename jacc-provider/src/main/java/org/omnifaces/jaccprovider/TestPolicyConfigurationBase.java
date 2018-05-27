package org.omnifaces.jaccprovider;
import static java.util.Collections.list;
 
import java.security.Permission;
import java.security.PermissionCollection;
 
import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyContextException;
 
public abstract class TestPolicyConfigurationBase implements PolicyConfiguration {
     
    private final String contextID;
     
    public TestPolicyConfigurationBase(String contextID) {
        this.contextID = contextID;
    }
     
    @Override
    public String getContextID() throws PolicyContextException {
        return contextID;
    }
     
    @Override
    public void addToExcludedPolicy(PermissionCollection permissions) throws PolicyContextException {
        for (Permission permission : list(permissions.elements())) {
            addToExcludedPolicy(permission);
        }
    }
     
    @Override
    public void addToUncheckedPolicy(PermissionCollection permissions) throws PolicyContextException {
        for (Permission permission : list(permissions.elements())) {
            addToUncheckedPolicy(permission);
        }
    }
     
    @Override
    public void addToRole(String roleName, PermissionCollection permissions) throws PolicyContextException {
        for (Permission permission : list(permissions.elements())) {
            addToRole(roleName, permission);
        }
    }
 
    @Override
    public void linkConfiguration(PolicyConfiguration link) throws PolicyContextException {
    }
     
    @Override
    public boolean inService() throws PolicyContextException {
        // Not used, taken care of by PolicyConfigurationStateMachine
        return true;
    }
 
}