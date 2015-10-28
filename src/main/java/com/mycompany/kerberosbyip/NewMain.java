/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.kerberosbyip;

import java.io.InputStream;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.Scanner;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.xml.soap.SOAPConstants;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthSchemeRegistry;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.client.methods.HttpPost;
import static org.apache.http.client.params.AuthPolicy.KERBEROS;
import static org.apache.http.client.params.AuthPolicy.SPNEGO;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.BasicClientConnectionManager;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

/**
 *
 * @author John Doe
 */
public class NewMain {

    /**
     * Put here real setting.
     */
    private static final String REALM = "CORP.DOMAIN.COM";
    private static final String KDC = "kdc.corp.domain.com";
    private static final String username = "john.doe@" + REALM;
    private static final String password = "password";
    private static final String ipAddress = "10.10.64.60";
    private static final int port = 5985;

    public static void main(String[] args) throws Exception {
        Logger logger = Logger.getLogger("org.apache.http");
        logger.setLevel(Level.TRACE);

        System.setProperty("sun.security.krb5.debug", "true");
        System.setProperty("java.security.krb5.realm", REALM);
        System.setProperty("java.security.krb5.kdc", KDC);

        ClassLoader classLoader = NewMain.class.getClassLoader();
        URL loginConf = classLoader.getResource("login.conf");
        System.setProperty("java.security.auth.login.config", loginConf.toString());

        NewMain m = new NewMain();
        m.runPrivileged();
    }

    private void runPrivileged() throws Exception {
        final CallbackHandler handler = new ProvidedAuthCallback(username, password);
        final LoginContext lc = new LoginContext("KrbLogin", handler);
        lc.login();

        PrivilegedAction<Void> sendAction = new PrivilegedAction<Void>() {
            @Override
            public Void run() {
                try {
                    doSendRequest();
                    return null;
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }

            }
        };

        Subject.doAs(lc.getSubject(), sendAction);
    }

    private void doSendRequest() throws Exception {

        InputStream stream = Thread.currentThread().getContextClassLoader().getResourceAsStream("request");
        String requestBody = new Scanner(stream, "UTF-8").useDelimiter("\\A").next();

        final DefaultHttpClient client = new DefaultHttpClient(new BasicClientConnectionManager());

        try {
            configureHttpClient(client);
            final HttpEntity entity = createEntity(requestBody);

            final HttpPost post = new HttpPost("/wsman");
            post.setHeader("Content-Type", SOAPConstants.SOAP_1_2_CONTENT_TYPE + "; charset=utf-8");
            post.setHeader("Connection", "Keep-Alive");
            post.setHeader("SOAPAction", "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate");
            post.setEntity(entity);

            final HttpResponse response = client.execute(new HttpHost(ipAddress, port, "http"), post);

            if (response.getStatusLine().getStatusCode() != 200) {
                throw new Exception(String.format("Unexpected HTTP response on %s:  %s (%s)",
                        ipAddress, response.getStatusLine().getReasonPhrase(), response.getStatusLine().getStatusCode()));
            }

        } finally {
            client.getConnectionManager().shutdown();
        }
    }

    protected HttpEntity createEntity(final String requestDocAsString) {
        return new StringEntity(requestDocAsString, ContentType.create("application/soap+xml", "UTF-8"));
    }

    private void configureHttpClient(final DefaultHttpClient httpclient) throws GeneralSecurityException {
        AuthSchemeRegistry registry = new AuthSchemeRegistry();
        registry.register(KERBEROS, new WsmanKerberosSchemeFactory(true, "WSMAN", ipAddress, port));
        registry.register(SPNEGO, new WsmanSPNegoSchemeFactory(true, "WSMAN", ipAddress, port));
        httpclient.setAuthSchemes(registry);

        final Credentials jaasCreds = new Credentials() {
            @Override
            public String getPassword() {
                return null;
            }

            @Override
            public Principal getUserPrincipal() {
                return null;
            }
        };

        httpclient.getCredentialsProvider().setCredentials(new AuthScope(null, -1, null), jaasCreds);
    }

}
