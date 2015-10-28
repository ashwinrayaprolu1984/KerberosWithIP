package com.mycompany.kerberosbyip;

import org.apache.http.impl.auth.KerberosScheme;
import org.apache.log4j.Logger;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;


class WsmanKerberosScheme extends KerberosScheme {

    private final String spnServiceClass;

    private final String spnAddress;

    private final int spnPort;

    public WsmanKerberosScheme(final boolean stripPort, final String spnServiceClass, final String spnAddress, final int spnPort) {
        super(stripPort);
        this.spnServiceClass = spnServiceClass;
        this.spnAddress = spnAddress;
        this.spnPort = spnPort;
    }

    @Override
    protected byte[] generateGSSToken(final byte[] input, final Oid oid, String authServer) throws GSSException {
        byte[] token = input;
        if (token == null) {
            token = new byte[0];
        }

        if (authServer.equals("localhost")) {
            if (authServer.indexOf(':') > 0) {
                authServer = spnAddress + ":" + spnPort;
            } else {
                authServer = spnAddress;
            }
        }

        String spn = spnServiceClass + "@" + authServer;

        logger.debug("Requesting Kerberos ticket for SPN {}" + spn);
        GSSManager manager = getManager();
        GSSName serverName = manager.createName(spn, GSSName.NT_HOSTBASED_SERVICE);
        GSSName canonicalizedName = serverName.canonicalize(oid);

        logger.debug("Creating Kerberos GSS context for canonicalized SPN {}" + canonicalizedName);
        GSSContext gssContext = manager.createContext(canonicalizedName, oid, null, GSSContext.DEFAULT_LIFETIME);
        gssContext.requestMutualAuth(true);
        gssContext.requestCredDeleg(true);
        return gssContext.initSecContext(token, 0, token.length);
    }

     private final Logger logger = Logger.getLogger(getClass());

}
