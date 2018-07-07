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

import javax.security.jacc.PolicyContext;
import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleListener;
import org.apache.openejb.core.ThreadContext;
import org.apache.openejb.core.ThreadContextListener;

/**
 * TomEE sets the PolicyContext context ID before calling an EJB, and resets the
 * old value after the call finishes. But that "old" value is not read from the
 * Policy, but from another context object so the context ID is set to
 * {@code null} when the component originating the call was not another EJB (eg.
 * a Servlet).
 *
 * This class registers a listener to reset the correct context ID after all
 * other TomEE listeners have already been called.
 * 
 * This class must be registered on the server.xml file as follows:
 * 
 * <code>
 * <Engine>
 *     ...
 *     <Listener className="org.omnifaces.jaccprovidertomee.catalina.ContextIdThreadContextListener" />
 * </Engine>
 * </code>
 *
 * @author Guillermo González de Agüero
 */
public class ContextIdThreadContextListener implements ThreadContextListener, LifecycleListener {

    private static final ThreadLocal<String> THREAD_CONTEXT_ID = new ThreadLocal<>();

    @Override
    public void lifecycleEvent(LifecycleEvent event) {
        if (Lifecycle.AFTER_START_EVENT.equals(event.getType())) {
            // This listener must be the latest
            ThreadContext.addThreadContextListener(new ContextIdThreadContextListener());
        }
    }

    @Override
    public void contextEntered(ThreadContext oldContext, ThreadContext newContext) {
        // There will always be a ContextID at this point
        THREAD_CONTEXT_ID.set(PolicyContext.getContextID());
    }

    @Override
    public void contextExited(ThreadContext exitedContext, ThreadContext reenteredContext) {
        // AbstractContextService puts again the original ContextID it had before entering an EJB.
        // That will be null if the call to the EJB was not another EJB (e.g. a Servlet), since it gets the ID from another place than the PolicyContext
        // This hack relies on the AbstractContextService#contextExited() method to be called BEFORE our code
        PolicyContext.setContextID(THREAD_CONTEXT_ID.get());
        THREAD_CONTEXT_ID.remove();
    }

}
