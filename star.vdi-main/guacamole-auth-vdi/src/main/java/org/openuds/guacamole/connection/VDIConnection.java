package org.openvdi.guacamole.connection;

import java.util.Map;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.net.auth.simple.SimpleConnection;
import org.apache.guacamole.protocol.GuacamoleClientInformation;
import org.openvdi.guacamole.VDIUserContext;

/**
 * Connection implementation which uses provided data to communicate with a 
 * remote VDI service to dynamically authorize access to a remote desktop. The
 * provided data is validated when the VDIConnection is created and upon each
 * connection attempt.
 */
public class VDIConnection extends SimpleConnection {

    /**
     * The name of the single connection that should be exposed to any user
     * that authenticates via VDI.
     */
    public static final String NAME = "VDI";

    /**
     * The unique identifier of the single connection that should be exposed to
     * any user that authenticates via VDI.
     */
    public static final String IDENTIFIER = NAME;

    /**
     * Service for retrieving configuration information.
     */
    private final ConnectionService connectionService;

    /**
     * The VDI-specific data that should be provided to the remote VDI service
     * to re-authenticate the user and determine the details of the connection
     * they are authorized to access.
     */
    private final String data;

    /**
     * Creates a new VDIConnection which exposes access to a remote desktop
     * that is dynamically authorized by exchanging arbitrary VDI-specific data
     * with a remote service. If the data is accepted by the VDI service, the
     * data will also be re-validated upon each connection attempt.
     *
     * @param connectionService
     *     The service that should be used to validate the provided VDI data
     *     and retrieve corresponding connection configuration information.
     *
     * @param data
     *     The VDI-specific data that should be provided to the remote VDI
     *     service.
     *
     * @throws GuacamoleException
     *     If the provided data is no longer valid or the VDI service does not
     *     respond successfully.
     */
    public VDIConnection(ConnectionService connectionService, String data)
            throws GuacamoleException {

        // Validate provided data
        super.setConfiguration(connectionService.getConnectionConfiguration(data));

        this.connectionService = connectionService;
        this.data = data;

    }

    @Override
    public String getParentIdentifier() {
        return VDIUserContext.ROOT_CONNECTION_GROUP;
    }

    @Override
    public void setParentIdentifier(String parentIdentifier) {
        throw new UnsupportedOperationException("VDIConnection is read-only.");
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public void setName(String name) {
        throw new UnsupportedOperationException("VDIConnection is read-only.");
    }

    @Override
    public String getIdentifier() {
        return IDENTIFIER;
    }

    @Override
    public void setIdentifier(String identifier) {
        throw new UnsupportedOperationException("VDIConnection is read-only.");
    }

    @Override
    public GuacamoleTunnel connect(GuacamoleClientInformation info,
            Map<String, String> tokens) throws GuacamoleException {

        // Re-validate provided data (do not allow connections if data is no
        // longer valid)
        super.setConfiguration(connectionService.getConnectionConfiguration(data));

        // Connect with configuration produced from data
        return super.connect(info, tokens);

    }

}
