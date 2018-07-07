## JACC Provider TomEE Bridge

TomEE enables JACC only for EJB calls, which makes it unusable from Servlet requests. This bridge simulates allows to do some basic stuff as it JACC were really enabled, like getting the Subject for the current request.

In order to use this, you'll need to:

* Copy the `jacc-provider.jar` and `tomee-bridge.jar` artifacts to the `$TOMEE_HOME/lib` folder.
* Edit your startup script (e.g. `catalina.sh`) to add the line: `export JAVA_OPTS="$JAVA_OPTS -Djavax.security.jacc.policy.provider=org.omnifaces.jaccprovider.TestPolicy -Djavax.security.jacc.PolicyConfigurationFactory.provider=org.omnifaces.jaccprovider.TestPolicyConfigurationFactory"`
* Add the following lines to $TOMEE_HOME/conf/server.xml under the `<Engine></Engine>` section:
```
<Valve className="org.omnifaces.jaccprovidertomee.JaccBridgeValve" />
<Listener className="org.omnifaces.jaccprovidertomee.catalina.ContextIdThreadContextListener" />
```

### Known limitations

TomEE only puts the EJB permissions on the PolicyConfiguration, so checking for `WebResourcePermission` won't work. That will need to be provided on a future revision.
