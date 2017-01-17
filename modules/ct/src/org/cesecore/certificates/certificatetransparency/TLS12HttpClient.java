package org.cesecore.certificates.certificatetransparency;

import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.ssl.SSLInitializationException;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;

import javax.net.ssl.SSLContext;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import static org.apache.http.conn.ssl.SSLSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER;

/**
 * It does the same that a regular {@link org.apache.http.impl.client.DefaultHttpClient} but it supports TLSv1.2 in Java 7
 * contrary to the default {@link org.apache.http.impl.client.DefaultHttpClient} which only supports up to TLSv1.
 */
class TLS12HttpClient extends DefaultHttpClient {

    /**
     * Copied and patched from {@link org.apache.http.conn.ssl.SSLSocketFactory#getSocketFactory()}.
     */
    private static SSLSocketFactory getSocketFactory() throws SSLInitializationException {
        SSLContext sslcontext;
        try {
            // TODO check if required to disable SSLv3. Note that it seems to be enabled by default in Java 7.
            // NOTE that this could fail in Java 6 which doesn't support TLSv1.2 (from https://blogs.oracle.com/java-platform-group/entry/diagnosing_tls_ssl_and_https). TODO evaluate to depend on the 'https.protocols' JVM property in a similar way that HttpsURLConnection instead of hardcoding TLSv1.2 protocol.
            sslcontext = SSLContext.getInstance("TLSv1.2");
            sslcontext.init(null, null, null);
            return new SSLSocketFactory(
                    sslcontext,
                    BROWSER_COMPATIBLE_HOSTNAME_VERIFIER);
        } catch (NoSuchAlgorithmException ex) {
            throw new SSLInitializationException(ex.getMessage(), ex);
        } catch (KeyManagementException ex) {
            throw new SSLInitializationException(ex.getMessage(), ex);
        }
    }

    @Override
    protected ClientConnectionManager createClientConnectionManager() {
        ClientConnectionManager clientConnectionManager = super.createClientConnectionManager();
        // Overriding the default for HTTPS.
        clientConnectionManager.getSchemeRegistry().register(
                new Scheme("https", 443, getSocketFactory()));
        return clientConnectionManager;
    }
}
