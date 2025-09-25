package org.openvdi.guacamole.config;

import com.google.inject.Inject;
import com.google.inject.Singleton;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.properties.URIGuacamoleProperty;

/**
 * Service that provides access to OpenVDI-specific configuration information
 * stored within guacamole.properties.
 */
@Singleton
public class ConfigurationService {

    /**
     * The name of the property within guacamole.properties which defines the
     * base URL of the service providing connection configuration information.
     */
    private static final URIGuacamoleProperty VDI_BASE_URL_PROPERTY = new URIGuacamoleProperty() {

        @Override
        public String getName() {
            return "vdi-base-url";
        }

    };

    /**
     * The Guacamole server environment.
     */
    @Inject
    private Environment environment;

    /**
     * Returns the base URI of the OpenVDI service. All services providing data
     * to this Guacamole integration are hosted beneath this base URI.
     *
     * @return
     *     The base URI of the OpenVDI service.
     *
     * @throws GuacamoleException
     *     If the base URI of the OpenVDI service is not defined because the
     *     tunnel.properties file could not be parsed when the web application
     *     started.
     */
    public URI getVDIBaseURI() throws GuacamoleException {
        return environment.getRequiredProperty(VDI_BASE_URL_PROPERTY);
    }

}
