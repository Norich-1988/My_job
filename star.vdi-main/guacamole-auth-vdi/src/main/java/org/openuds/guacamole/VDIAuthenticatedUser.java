package org.openvdi.guacamole;

import org.apache.guacamole.net.auth.AbstractAuthenticatedUser;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.AuthenticationProvider;
import org.apache.guacamole.net.auth.Credentials;
import org.openvdi.guacamole.connection.VDIConnection;

/**
 * A Guacamole user that was authenticated by an external VDI service.
 */
public class VDIAuthenticatedUser extends AbstractAuthenticatedUser {

    /**
     * The AuthenticationProvider that authenticated this user.
     */
    private final AuthenticationProvider authProvider;

    /**
     * The credentials provided by this user when they authenticated.
     */
    private final Credentials credentials;

    /**
     * The single connection that this user should be authorized to access.
     */
    private final VDIConnection connection;

    /**
     * Creates a new VDIAuthenticatedUser representing a Guacamole user that
     * was authenticated by an external VDI service.
     *
     * @param authProvider
     *     The AuthenticationProvider that authenticated the user.
     *
     * @param credentials
     *     The credentials provided by the user when they authenticated.
     *
     * @param connection
     *     The single connection that the user should be authorized to access.
     */
    public VDIAuthenticatedUser(AuthenticationProvider authProvider,
            Credentials credentials, VDIConnection connection) {
        this.authProvider = authProvider;
        this.credentials = credentials;
        this.connection = connection;
    }

    @Override
    public String getIdentifier() {
        return AuthenticatedUser.ANONYMOUS_IDENTIFIER;
    }

    @Override
    public AuthenticationProvider getAuthenticationProvider() {
        return authProvider;
    }

    @Override
    public Credentials getCredentials() {
        return credentials;
    }

    /**
     * Returns the single connection that this user should be authorized to
     * access.
     *
     * @return
     *     The single connection that this user should be authorized to access.
     */
    public VDIConnection getConnection() {
        return connection;
    }

}
