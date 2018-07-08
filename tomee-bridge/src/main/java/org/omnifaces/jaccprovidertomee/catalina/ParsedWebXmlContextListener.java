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
        if (event.getType().equals(Lifecycle.BEFORE_START_EVENT)) {
            return;
        }

        Context context = (Context) event.getLifecycle();

        SpecSecurityBuilder specSecurityBuilder = new SpecSecurityBuilder(context);

        System.out.println("-------" + context.getName() + "--------");
        System.out.println(specSecurityBuilder.buildSpecSecurityConfig());
        System.out.println("----------------------------------------");
    }
}
