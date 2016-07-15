package org.omnifaces.jaccprovider;
import javax.security.jacc.PolicyContextException;
 
public class TestPolicyConfiguration extends TestPolicyConfigurationPermissions {
 
    public TestPolicyConfiguration(String contextID) {
        super(contextID);
    }
     
    private TestRoleMapper roleMapper;
 
    @Override
    public void commit() throws PolicyContextException {
        roleMapper = new TestRoleMapper(getContextID(), getPerRolePermissions().keySet());
    }
     
    public TestRoleMapper getRoleMapper() {
        return roleMapper;
    }
 
}