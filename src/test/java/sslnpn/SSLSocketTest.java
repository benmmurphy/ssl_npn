package sslnpn;

import static org.junit.Assert.assertEquals;

import java.net.InetSocketAddress;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.net.ssl.SSLContext;

import org.junit.Before;
import org.junit.Test;

import sslnpn.ssl.SSLServerSocketImpl;
import sslnpn.ssl.SSLSocketImpl;

public class SSLSocketTest {

    private SSLContext context;
    
    @Before
    public void before() throws Exception {
        context = SSLContextCreator.newContext();
    }
    
    @Test
    public void testConnectToServerWithFallback() throws Exception {
        PortAndFuture portAndFuture = spawnServer("http/1.1", "spdy/2");
        SSLSocketImpl clientSocket = (SSLSocketImpl) context.getSocketFactory().createSocket();
        try {
            clientSocket.setNextProtocolNegotiationFallbackAndChoices("spdy/3", "spdy/3");

            clientSocket.connect(new InetSocketAddress("127.0.0.1", portAndFuture.port));
            clientSocket.startHandshake();
            assertEquals("spdy/3", clientSocket.getNegotiatedNextProtocol());
            assertEquals("spdy/3", portAndFuture.future.get());
        } finally {
            clientSocket.close();
        }
    }

    private static class PortAndFuture {
        private int port;
        private Future<String> future;
        public PortAndFuture(int port, Future<String> future) {
            this.port = port;
            this.future = future;
        }
    }
    
    private PortAndFuture spawnServer(final String... protocols) throws Exception {
        final SSLServerSocketImpl socket = (SSLServerSocketImpl) context.getServerSocketFactory().createServerSocket();
        socket.bind(null);
        
        int port = socket.getLocalPort();
        
        Future<String> future = Executors.newCachedThreadPool().submit(new Callable<String>() {

            @Override
            public String call() throws Exception {
                try {
                    socket.setAdvertisedNextProtocols(protocols);
                    SSLSocketImpl clientSocket = (SSLSocketImpl) socket.accept();
                    try {
                        clientSocket.startHandshake();

                        return clientSocket.getNegotiatedNextProtocol();
                    } finally {
                        clientSocket.close();
                    }
                } finally {
                    socket.close();
                }
            }
            
        });

        
        return new PortAndFuture(port, future);
    }
}
