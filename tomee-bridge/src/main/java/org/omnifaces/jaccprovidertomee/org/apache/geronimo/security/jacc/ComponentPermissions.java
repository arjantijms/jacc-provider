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
package org.omnifaces.jaccprovidertomee.org.apache.geronimo.security.jacc;

import java.io.Serializable;
import java.security.PermissionCollection;
import java.util.Map;

/**
 *
 * @author Guillermo González de Agüero
 */
public class ComponentPermissions implements Serializable {

    private final PermissionCollection excludedPermissions;
    private final PermissionCollection uncheckedPermissions;
    private final Map<String, PermissionCollection> rolePermissions;

    public ComponentPermissions(PermissionCollection excludedPermissions, PermissionCollection uncheckedPermissions, Map<String, PermissionCollection> rolePermissions) {
        this.excludedPermissions = excludedPermissions;
        this.uncheckedPermissions = uncheckedPermissions;
        this.rolePermissions = rolePermissions;
    }

    public PermissionCollection getExcludedPermissions() {
        return excludedPermissions;
    }

    public PermissionCollection getUncheckedPermissions() {
        return uncheckedPermissions;
    }

    public Map<String, PermissionCollection> getRolePermissions() {
        return rolePermissions;
    }

    @Override
    public String toString() {
        return "ComponentPermissions{" + "excludedPermissions=" + excludedPermissions + ", uncheckedPermissions=" + uncheckedPermissions + ", rolePermissions=" + rolePermissions + '}';
    }

}
