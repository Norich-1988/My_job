package org.openvdi.guacamole;

import java.util.Collections;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.auth.AbstractUserContext;
import org.apache.guacamole.net.auth.AuthenticationProvider;
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.Directory;
import org.apache.guacamole.net.auth.User;
import org.apache.guacamole.net.auth.permission.ObjectPermissionSet;
import org.apache.guacamole.net.auth.simple.SimpleDirectory;
import org.apache.guacamole.net.auth.simple.SimpleObjectPermissionSet;
import org.apache.guacamole.net.auth.simple.SimpleUser;
import org.openvdi.guacamole.connection.VDIConnection;

/**
 * UserContext implementation which exposes access only to a single
 * VDIConnection. The details of the connection exposed are determined by the
 * VDI-specific data associated with the user.
 */
public class VDIUserContext extends AbstractUserContext {

    /**
     * The unique identifier of the root connection group.
     */
    public static final String ROOT_CONNECTION_GROUP = DEFAULT_ROOT_CONNECTION_GROUP;

    /**
     * The AuthenticationProvider that produced this UserContext.
     */
    private final AuthenticationProvider authProvider;

    /**
     * The AuthenticatedUser for whom this UserContext was created.
     */
    private final VDIAuthenticatedUser authenticatedUser;

    /**
     * Creates a new VDIUserContext that is associated with the given
     * AuthenticationProvider and uses the VDI-specific data of the given
     * VDIAuthenticatedUser to determine the connection that user can access.
     *
     * @param authProvider
     *     The AuthenticationProvider that is producing the UserContext.
     *
     * @param authenticatedUser
     *     The AuthenticatedUser for whom this UserContext is being created.
     */
    public VDIUserContext(AuthenticationProvider authProvider,
            VDIAuthenticatedUser authenticatedUser) {
        this.authProvider = authProvider;
        this.authenticatedUser = authenticatedUser;
    }

    @Override
    public User self() {
        return new SimpleUser() {

            @Override
            public ObjectPermissionSet getConnectionGroupPermissions() throws GuacamoleException {
                return new SimpleObjectPermissionSet(Collections.singleton(DEFAULT_ROOT_CONNECTION_GROUP));
            }

            @Override
            public ObjectPermissionSet getConnectionPermissions() throws GuacamoleException {
                return new SimpleObjectPermissionSet(Collections.singleton(VDIConnection.IDENTIFIER));
            }

        };
    }

    @Override
    public AuthenticationProvider getAuthenticationProvider() {
        return authProvider;
    }

    @Override
    public Directory<Connection> getConnectionDirectory() throws GuacamoleException {
        return new SimpleDirectory<>(authenticatedUser.getConnection());
    }

}
