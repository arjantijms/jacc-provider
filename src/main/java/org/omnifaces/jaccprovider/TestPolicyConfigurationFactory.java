package org.omnifaces.jaccprovider;
import static javax.security.jacc.PolicyContext.getContextID;
 
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
 
import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyConfigurationFactory;
import javax.security.jacc.PolicyContextException;
 
public class TestPolicyConfigurationFactory extends PolicyConfigurationFactory {
     
    private static final ConcurrentMap<String, TestPolicyConfigurationStateMachine> configurators = new ConcurrentHashMap<>();
 
    @Override
    public PolicyConfiguration getPolicyConfiguration(String contextID, boolean remove) throws PolicyContextException {
         
        if (!configurators.containsKey(contextID)) {
            configurators.putIfAbsent(contextID, new TestPolicyConfigurationStateMachine(new TestPolicyConfiguration(contextID)));
        }
         
        TestPolicyConfigurationStateMachine testPolicyConfigurationStateMachine = configurators.get(contextID);
         
        if (remove) {
            testPolicyConfigurationStateMachine.delete();
        }
         
        // According to the contract of getPolicyConfiguration() every PolicyConfiguration returned from here
        // should always be transitioned to the OPEN state.
        testPolicyConfigurationStateMachine.open();
         
        return testPolicyConfigurationStateMachine;
    }
     
    @Override
    public boolean inService(String contextID) throws PolicyContextException {
        TestPolicyConfigurationStateMachine testPolicyConfigurationStateMachine = configurators.get(contextID);
        if (testPolicyConfigurationStateMachine == null) {
            return false;
        }
         
        return testPolicyConfigurationStateMachine.inService();
    }
     
    public static TestPolicyConfiguration getCurrentPolicyConfiguration() {
        return (TestPolicyConfiguration) configurators.get(getContextID()).getPolicyConfiguration();
    }
     
}