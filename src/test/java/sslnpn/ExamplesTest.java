package sslnpn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.junit.Before;
import org.junit.Test;

import sslnpn.OpenSSLCompatabilityTest.Chooser;
import sslnpn.OpenSSLCompatabilityTest.SpawnSSLClient;
import sslnpn.ssl.SSLEngineImpl;
import sslnpn.ssl.SSLSocketImpl;

public class ExamplesTest {

    private SSLContext context;

    @Before
    public void before() throws Exception {
        context = newContext();
    }

    /* just testing the examples in README.md compile */

    
    public void testClient() throws Exception {
        SSLSocketFactory factory = context.getSocketFactory();
        sslnpn.ssl.SSLSocketImpl socket = (sslnpn.ssl.SSLSocketImpl) factory.createSocket();
        socket.setNpnChooser(new sslnpn.ssl.NextProtocolNegotiationChooser() {
            @Override
            public String chooseProtocol(List<String> protocols) {
                if (protocols.contains("spdy/2")) {
                    return "spdy/2";
                } else {
                    /* you can also return null here to bail the connection */
                    return "http/1.1";
                }
            }
        });

        socket.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), 443));
        String protocol = socket.getNegotiatedNextProtocol();
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

    public void testClientEngine() throws Exception {
        SocketChannel socket = SocketChannel.open();
        socket.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), 443));

        sslnpn.ssl.SSLEngineImpl engine = (sslnpn.ssl.SSLEngineImpl) context.createSSLEngine();

        engine.setNpnChooser(new sslnpn.ssl.NextProtocolNegotiationChooser() {
            @Override
            public String chooseProtocol(List<String> protocols) {
                if (protocols.contains("spdy/2")) {
                    return "spdy/2";
                } else {
                    /* you can also return null here to bail the connection */
                    return "http/1.1";
                }
            }
        });

        engine.setUseClientMode(true);

        negotiateHandshake(engine, socket);
        String protocol = engine.getNegotiatedNextProtocol();
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

    private void negotiateHandshake(SSLEngineImpl engine, SocketChannel socket) {

    }

    private SSLContext newContext() throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException,
            CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException {

        SSLContext context = SSLContext.getInstance("Default", new sslnpn.net.ssl.internal.ssl.Provider());
        return context;
    }
}
