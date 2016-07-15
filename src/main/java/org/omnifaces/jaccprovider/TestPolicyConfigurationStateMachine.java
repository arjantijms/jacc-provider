package org.omnifaces.jaccprovider;
import static org.omnifaces.jaccprovider.TestPolicyConfigurationStateMachine.State.DELETED;
import static org.omnifaces.jaccprovider.TestPolicyConfigurationStateMachine.State.INSERVICE;
import static org.omnifaces.jaccprovider.TestPolicyConfigurationStateMachine.State.OPEN;

import java.security.Permission;
import java.security.PermissionCollection;

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyConfigurationFactory;
import javax.security.jacc.PolicyContextException;
 
public class TestPolicyConfigurationStateMachine implements PolicyConfiguration {
 
    public static enum State {
        OPEN, INSERVICE, DELETED
    };
 
    private State state = OPEN;
    private PolicyConfiguration policyConfiguration;
     
 
    public TestPolicyConfigurationStateMachine(PolicyConfiguration policyConfiguration) {
        this.policyConfiguration = policyConfiguration;
    }
     
    public PolicyConfiguration getPolicyConfiguration() {
        return policyConfiguration;
    }
 
     
    // ### Methods that can be called in any state and don't change state
     
    @Override
    public String getContextID() throws PolicyContextException {
        return policyConfiguration.getContextID();
    }
     
    @Override
    public boolean inService() throws PolicyContextException {
        return state == INSERVICE;
    }
     
     
    // ### Methods where state should be OPEN and don't change state
     
    @Override
    public void addToExcludedPolicy(Permission permission) throws PolicyContextException {
        checkStateIs(OPEN);
        policyConfiguration.addToExcludedPolicy(permission);
    }
 
    @Override
    public void addToUncheckedPolicy(Permission permission) throws PolicyContextException {
        checkStateIs(OPEN);
        policyConfiguration.addToUncheckedPolicy(permission);
    }
 
    @Override
    public void addToRole(String roleName, Permission permission) throws PolicyContextException {
        checkStateIs(OPEN);
        policyConfiguration.addToRole(roleName, permission);
    }
     
    @Override
    public void addToExcludedPolicy(PermissionCollection permissions) throws PolicyContextException {
        checkStateIs(OPEN);
        policyConfiguration.addToExcludedPolicy(permissions);
    }
     
    @Override
    public void addToUncheckedPolicy(PermissionCollection permissions) throws PolicyContextException {
        checkStateIs(OPEN);
        policyConfiguration.addToUncheckedPolicy(permissions);
    }
     
    @Override
    public void addToRole(String roleName, PermissionCollection permissions) throws PolicyContextException {
        checkStateIs(OPEN);
        policyConfiguration.addToRole(roleName, permissions);
    }
     
    @Override
    public void linkConfiguration(PolicyConfiguration link) throws PolicyContextException {
        checkStateIs(OPEN);
        policyConfiguration.linkConfiguration(link);
    }
     
    @Override
    public void removeExcludedPolicy() throws PolicyContextException {
        checkStateIs(OPEN);
        policyConfiguration.removeExcludedPolicy();
         
    }
 
    @Override
    public void removeRole(String roleName) throws PolicyContextException {
        checkStateIs(OPEN);
        policyConfiguration.removeRole(roleName);
    }
 
    @Override
    public void removeUncheckedPolicy() throws PolicyContextException {
        checkStateIs(OPEN);
        policyConfiguration.removeUncheckedPolicy();
    }
     
     
    // Methods that change the state
    //
    // commit() can only be called when the state is OPEN or INSERVICE and next state is always INSERVICE
    // delete() can always be called and target state will always be DELETED
    // open()   can always be called and target state will always be OPEN
     
    @Override
    public void commit() throws PolicyContextException {
        checkStateIsNot(DELETED);
         
        if (state == OPEN) {
            // Not 100% sure; allow double commit, or ignore double commit?
            // Here we ignore and only call commit on the actual policyConfiguration
            // when the state is OPEN
            policyConfiguration.commit();
            state = INSERVICE;
        }
    }
 
    @Override
    public void delete() throws PolicyContextException {
        policyConfiguration.delete();
        state = DELETED;
    }
     
    /**
     * Transition back to open. This method is required because of the {@link PolicyConfigurationFactory} contract, but is
     * mysteriously missing from the interface.
     */
    public void open() {
        state = OPEN;
    }
     
     
    // ### Private methods
     
    private void checkStateIs(State requiredState) {
        if (state != requiredState) {
            throw new IllegalStateException("Required status is " + requiredState + " but actual state is " + state);
        }
    }
     
    private void checkStateIsNot(State undesiredState) {
        if (state == undesiredState) {
            throw new IllegalStateException("State could not be " + undesiredState + " but actual state is");
        }
    }
 
}