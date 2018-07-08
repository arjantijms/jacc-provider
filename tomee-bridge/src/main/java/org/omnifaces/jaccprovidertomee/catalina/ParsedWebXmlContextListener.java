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
package org.omnifaces.jaccprovidertomee.catalina;

import javax.security.jacc.PolicyConfiguration;
import javax.security.jacc.PolicyConfigurationFactory;
import javax.security.jacc.PolicyContextException;
import org.apache.catalina.Context;
import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleListener;
import org.omnifaces.jaccprovidertomee.org.apache.geronimo.web.security.SpecSecurityBuilder;

/**
 *
 * @author Guillermo González de Agüero
 */
public class ParsedWebXmlContextListener implements LifecycleListener {

    @Override
    public void lifecycleEvent(LifecycleEvent event) {
        if (!event.getType().equals(Lifecycle.AFTER_START_EVENT)) {
            return;
        }

        Context context = (Context) event.getLifecycle();

        // At this point all Servlet registration has been done. It's safe to generate the definitive PolicyConfiguration
        PolicyConfiguration policyConfiguration;
        boolean needsCommit;
        try {
            String contextId = "file:" + context.getServletContext().getRealPath("");
            
            PolicyConfigurationFactory policyConfigurationFactory = PolicyConfigurationFactory.getPolicyConfigurationFactory();

            needsCommit = policyConfigurationFactory.inService(contextId);
            policyConfiguration = policyConfigurationFactory.getPolicyConfiguration(contextId, false);

            SpecSecurityBuilder specSecurityBuilder = new SpecSecurityBuilder(context, policyConfiguration);
            specSecurityBuilder.buildSpecSecurityConfig();

            if (needsCommit) {
                policyConfiguration.commit();
            }
        } catch (ClassNotFoundException | PolicyContextException e) {
            throw new RuntimeException(e);
        }
    }
}
