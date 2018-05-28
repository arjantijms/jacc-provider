package org.omnifaces.jaccproviderliberty;

import com.ibm.wsspi.security.authorization.jacc.ProviderService;
import java.security.Policy;
import java.util.Map;
import javax.security.jacc.PolicyConfigurationFactory;
import org.omnifaces.jaccprovider.TestPolicy;
import org.omnifaces.jaccprovider.TestPolicyConfigurationFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;

@Component(
	service = ProviderService.class,
	immediate = true,
	property = {
		"javax.security.jacc.policy.provider=org.omnifaces.jaccprovider.TestPolicy",
		"javax.security.jacc.PolicyConfigurationFactory.provider=org.omnifaces.jaccprovider.TestPolicyConfigurationFactory"
	}
)
public class MyJaccProviderService implements ProviderService {

	@Override
	public Policy getPolicy() {
		return new TestPolicy();
	}

	@Override
	public PolicyConfigurationFactory getPolicyConfigFactory() {
		ClassLoader cl = null;
		PolicyConfigurationFactory pcf = null;
		
		System.setProperty("javax.security.jacc.PolicyConfigurationFactory.provider", TestPolicyConfigurationFactory.class.getName());
		try {
			cl = Thread.currentThread().getContextClassLoader();
			Thread.currentThread().setContextClassLoader(
					this.getClass().getClassLoader());
			pcf = PolicyConfigurationFactory.getPolicyConfigurationFactory();
		} catch (Exception e) {
			return null;
		} finally {
			Thread.currentThread().setContextClassLoader(cl);
		}
		return pcf;
	}

	@Activate
	protected void activate(ComponentContext cc) {
	}

	@Deactivate
	protected void deactivate(ComponentContext cc) {
	}

}
