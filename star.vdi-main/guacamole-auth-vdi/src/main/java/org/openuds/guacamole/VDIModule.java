package org.openvdi.guacamole;

import com.google.inject.AbstractModule;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;
import org.openvdi.guacamole.config.ConfigurationService;
import org.openvdi.guacamole.connection.ConnectionService;

/**
 * Guice module which binds classes required by the OpenVDI integration of
 * Apache Guacamole.
 */
public class VDIModule extends AbstractModule {

    /**
     * The Guacamole server environment.
     */
    private final Environment environment;

    /**
     * Creates a new VDIModule which binds classes required by the OpenVDI
     * integration of Apache Guacamole, including an implementation of the
     * Guacamole server {@link Environment}.
     *
     * @throws GuacamoleException
     *     If the guacamole.properties file cannot be read.
     */
    public VDIModule() throws GuacamoleException {
        this.environment = new LocalEnvironment();
    }

    @Override
    protected void configure() {

        // Bind instance of Guacamole server environment
        bind(Environment.class).toInstance(environment);

        // Bind VDI-specific services
        bind(ConfigurationService.class);
        bind(ConnectionService.class);

    }
    
}
