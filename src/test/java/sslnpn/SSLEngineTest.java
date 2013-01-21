package sslnpn;

import static org.junit.Assert.assertEquals;

import java.net.InetSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.net.ssl.SSLContext;

import org.junit.Before;
import org.junit.Test;

import sslnpn.ssl.SSLEngineImpl;

public class SSLEngineTest {

  private SSLContext context;
    
    @Before
    public void before() throws Exception {
        context = SSLContextCreator.newContext();
    }
    
    @Test
    public void testConnectToServerWithFallback() throws Exception {
        PortAndFuture portAndFuture = spawnServer("http/1.1", "spdy/2");
        SSLEngineImpl engine = (SSLEngineImpl) context.createSSLEngine();
        SocketChannel channel = SocketChannel.open();
        try {
            channel.connect(new InetSocketAddress("127.0.0.1", portAndFuture.port));
            engine.setNextProtocolNegotiationFallbackAndChoices("spdy/3", "spdy/3");
            engine.setUseClientMode(true);
            SSLEngineHandshaker.negotiateHandshake(engine, channel);
            
            assertEquals("spdy/3", engine.getNegotiatedNextProtocol());
            assertEquals("spdy/3", portAndFuture.future.get());
        } finally {
            channel.close();
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
        final ServerSocketChannel channel = ServerSocketChannel.open();
        

        channel.bind(null);
        
        int port = ((InetSocketAddress)channel.getLocalAddress()).getPort();
        
        Future<String> future = Executors.newCachedThreadPool().submit(new Callable<String>() {

            @Override
            public String call() throws Exception {
                try {

                    SocketChannel clientChannel = channel.accept();
                    try {
                        final SSLEngineImpl engine = (SSLEngineImpl) context.createSSLEngine();
                        engine.setUseClientMode(false);
                        engine.setAdvertisedNextProtocols(protocols);
                        SSLEngineHandshaker.negotiateHandshake(engine, clientChannel);

                        return engine.getNegotiatedNextProtocol();
                    } finally {
                        clientChannel.close();
                    }
                } finally {
                    channel.close();
                }
            }
            
        });

        
        return new PortAndFuture(port, future);
    }
}
