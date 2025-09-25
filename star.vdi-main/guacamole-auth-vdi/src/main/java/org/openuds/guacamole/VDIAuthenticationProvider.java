package org.openvdi.guacamole;

import com.google.inject.Guice;
import com.google.inject.Injector;
import java.util.Collections;
import javax.servlet.http.HttpServletRequest;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.form.Field;
import org.apache.guacamole.net.auth.AbstractAuthenticationProvider;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.UserContext;
import org.apache.guacamole.net.auth.credentials.CredentialsInfo;
import org.apache.guacamole.net.auth.credentials.GuacamoleInvalidCredentialsException;
import org.openvdi.guacamole.connection.ConnectionService;
import org.openvdi.guacamole.connection.VDIConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * AuthenticationProvider implementation which authenticates users that are
 * confirmed as authorized by an external VDI service.
 */
public class VDIAuthenticationProvider extends AbstractAuthenticationProvider {

    /**
     * The name of the query parameter that should contain the data sent to
     * the VDI service for authentication.
     */
    private static final String DATA_PARAMETER_NAME = "data";

    /**
     * The form of credentials accepted by this extension.
     */
    private static final CredentialsInfo VDI_CREDENTIALS =
            new CredentialsInfo(Collections.<Field>singletonList(
                new Field(DATA_PARAMETER_NAME, Field.Type.QUERY_PARAMETER)
            ));

    /**
     * Logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(VDIAuthenticationProvider.class);

    /**
     * Service for retrieving connection configuration information from the
     * VDI service.
     */
    private final ConnectionService connectionService;

    /**
     * Creates a new VDIAuthenticationProvider which authenticates users
     * against an external VDI service.
     *
     * @throws GuacamoleException
     *     If an error prevents guacamole.properties from being read.
     */
    public VDIAuthenticationProvider() throws GuacamoleException {

        // Create an injector with OpenVDI- and Guacamole-specific services
        // properly bound
        Injector injector = Guice.createInjector(
            new VDIModule()
        );

        // Pull instance of connection service from injector
        connectionService = injector.getInstance(ConnectionService.class);

    }

    @Override
    public String getIdentifier() {
        return "vdi";
    }

    @Override
    public AuthenticatedUser authenticateUser(Credentials credentials)
            throws GuacamoleException {

        HttpServletRequest request = credentials.getRequest();

        // Pull OpenVDI-specific "data" parameter
        String data = request.getParameter(DATA_PARAMETER_NAME);
        if (data == null || data.isEmpty()) {
            logger.debug("VDI connection data was not provided. No connection retrieval from VDI will be performed.");
            throw new GuacamoleInvalidCredentialsException("Connection data was not provided.", VDI_CREDENTIALS);
        }

        try {

            // Retrieve connection information using provided data
            VDIConnection connection = new VDIConnection(connectionService, data);

            // Report successful authentication as a temporary, anonymous user,
            // storing the retrieved connection configuration data for future use
            return new VDIAuthenticatedUser(this, credentials, connection);

        }
        catch (GuacamoleException e) {
            logger.info("Provided connection data could not be validated with VDI: {}", e.getMessage());
            logger.debug("Validation of VDI connection data failed.", e);
            throw new GuacamoleInvalidCredentialsException("Connection data was rejected by VDI.", e, VDI_CREDENTIALS);
        }

    }

    @Override
    public UserContext getUserContext(AuthenticatedUser authenticatedUser)
            throws GuacamoleException {

        // Provide data only for users authenticated by this extension
        if (!(authenticatedUser instanceof VDIAuthenticatedUser))
            return null;

        // Expose a single connection (derived from the "data" parameter
        // provided during authentication)
        return new VDIUserContext(this, (VDIAuthenticatedUser) authenticatedUser);

    }

}
