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

import java.io.IOException;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.ServletException;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.omnifaces.jaccprovidertomee.ServletPolicyContextHandler;

/**
 * Catalina Valve that registers the missing PolicyContextHandlers and sets the
 * PolicyContext context ID, which TomEE only sets during EJB calls.
 * 
 * This class must be registered on your server.xml file as follows:
 * 
 * <code>
 * <Engine>
 *     ...
 *     <Valve className="org.omnifaces.jaccprovidertomee.JaccBridgeValve" />
 * </Engine>
 * </code>
 *
 * @author Guillermo González de Agüero
 */
public class JaccBridgeValve extends ValveBase {

    static {
        try {
            for (String key : ServletPolicyContextHandler.KEYS) {
                PolicyContext.registerHandler(key, ServletPolicyContextHandler.getInstance(), false);
            }
        } catch (PolicyContextException ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        try {
            // TomEE uses the deployment path as the context ID
            PolicyContext.setContextID(request.getRealPath(""));

            ServletPolicyContextHandler.startRequest(request);
            getNext().invoke(request, response);
        } finally {
            ServletPolicyContextHandler.completeRequest();
        }
    }

}
