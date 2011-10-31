package sslnpn;

import static org.junit.Assert.assertEquals;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;

import org.junit.Before;
import org.junit.Test;

import sslnpn.ssl.SSLEngineImpl;

public class ExamplesTest {

    private SSLContext context;

    @Before
    public void before() throws Exception {
        System.setProperty("javax.net.debug", "all");
        context = newContext();
    }

    /* just testing the examples in README.md compile */

   
    @Test 
    public void testClient() throws Exception {
        SSLSocketFactory factory = context.getSocketFactory();
        sslnpn.ssl.SSLSocketImpl socket = (sslnpn.ssl.SSLSocketImpl) factory.createSocket();
        socket.setNextProtocolNegotiationFallbackAndChoices("http/1.1", "spdy/2", "http/1.1");
        
        /* can also use null for the fallback to cause a failure during handshake if the selected protcol is not available */
        socket.setNextProtocolNegotiationFallbackAndChoices(null, "spdy/2", "http/1.1");

        /* can also use the following which will cause a failure during handshake if the selected protocol is not available  */
        socket.setNextProtocolNegotiationChoices("spdy/2", "http/1.1");

        socket.connect(new InetSocketAddress(InetAddress.getByName("www.google.com"), 443));
        socket.startHandshake();
        String protocol = socket.getNegotiatedNextProtocol();
        assertEquals("spdy/2", protocol);
    }

    public void testServer() throws Exception {
        SSLServerSocketFactory factory = context.getServerSocketFactory();
        sslnpn.ssl.SSLServerSocketImpl serverSocket = (sslnpn.ssl.SSLServerSocketImpl) factory.createServerSocket();
        serverSocket.setAdvertisedNextProtocols("http/1.1", "spdy/2");

        sslnpn.ssl.SSLSocketImpl socket = (sslnpn.ssl.SSLSocketImpl) serverSocket.accept();
        socket.startHandshake();

        String protocol = socket.getNegotiatedNextProtocol();
        /*
         * can be null if the client does not perform protocol negotiation also,
         * does not have to be one of the advertised protocols.
         */

    }

    @Test
    public void testClientEngine() throws Exception {
        SocketChannel socket = SocketChannel.open();
        socket.connect(new InetSocketAddress("www.google.com", 443));

        sslnpn.ssl.SSLEngineImpl engine = (sslnpn.ssl.SSLEngineImpl) context.createSSLEngine();
        engine.setNextProtocolNegotiationFallbackAndChoices("http/1.1", "spdy/2", "http/1.1");

        /* can also use null for the fallback to cause a failure during handshake if the selected protcol is not available */
        engine.setNextProtocolNegotiationFallbackAndChoices(null, "spdy/2", "http/1.1");

        /* can also use the following which will cause a failure during handshake if the selected protocol is not available */
        engine.setNextProtocolNegotiationChoices("spdy/2", "http/1.1");                       

        engine.setUseClientMode(true);

        negotiateHandshake(engine, socket);
        String protocol = engine.getNegotiatedNextProtocol();
        assertEquals("spdy/2", protocol);
    }

   
    public void testServerEngine() throws Exception {
        ServerSocketChannel serverSocket = ServerSocketChannel.open();
        serverSocket.bind(new InetSocketAddress(443));

        sslnpn.ssl.SSLEngineImpl engine = (sslnpn.ssl.SSLEngineImpl) context.createSSLEngine();
        engine.setAdvertisedNextProtocols("http/1.1", "spdy/2");
        SocketChannel socket = serverSocket.accept();
        engine.setUseClientMode(false);
        negotiateHandshake(engine, socket);

        String protocol = engine.getNegotiatedNextProtocol();

    }

    private void negotiateHandshake(SSLEngineImpl engine, SocketChannel socket) throws SSLException, IOException {
        SSLEngineHandshaker.negotiateHandshake(engine, socket);
    }

    private SSLContext newContext() throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException,
            CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException {

        SSLContext context = SSLContext.getInstance("Default", new sslnpn.net.ssl.internal.ssl.Provider());
        return context;
    }
}
