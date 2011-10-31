# About

This provides next protocol negotiation support for java. It is based off the openjdk ssl provider. 

http://tools.ietf.org/html/draft-agl-tls-nextprotoneg-00.html
http://tools.ietf.org/html/draft-agl-tls-nextprotoneg-02
https://technotes.googlecode.com/git/nextprotoneg.html

# Download

https://github.com/downloads/benmmurphy/ssl_npn/ssl_npn-0.1-SNAPSHOT.jar

# Using

## Creating an SSL Context

Creating an SSL Context is similar to how it is done normally but you pass in an explicit provider. For example:

    SSLContext context = SSLContext.getInstance("Default", new sslnpn.net.ssl.internal.ssl.Provider());

## SSL Socket Client
    SSLSocketFactory factory = context.getSocketFactory();
    sslnpn.ssl.SSLSocketImpl socket = (sslnpn.ssl.SSLSocketImpl) factory.createSocket();
    socket.setNextProtocolNegotiationFallbackAndChoices("http/1.1", "spdy/2", "http/1.1");

    /* can also use the following which will cause a failure during handshake if the selected protocol is not available */
    socket.setNextProtocolNegotiationChoices("spdy/2", "http/1.1");

    socket.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), 443));
    String protocol = socket.getNegotiatedNextProtocol(); /* will return null if npn negotiation was not performed */


## SSL Socket Server
    
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
    
## SSL Client Engine

    SocketChannel socket = SocketChannel.open();
    socket.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), 443));

    sslnpn.ssl.SSLEngineImpl engine = (sslnpn.ssl.SSLEngineImpl) context.createSSLEngine();

    engine.setNextProtocolNegotiationFallbackAndChoices("http/1.1", "spdy/2", "http/1.1");

    /* can also use the following which will cause a failure during handshake if the selected protocol is not available */
    engine.setNextProtocolNegotiationChoices("spdy/2", "http/1.1");

    engine.setUseClientMode(true);

    negotiateHandshake(engine, socket);
    String protocol = engine.getNegotiatedNextProtocol();
    
## SSL Server Engine
    ServerSocketChannel serverSocket = ServerSocketChannel.open();
    serverSocket.bind(new InetSocketAddress(443));

    sslnpn.ssl.SSLEngineImpl engine = (sslnpn.ssl.SSLEngineImpl) context.createSSLEngine();
    engine.setAdvertisedNextProtocols("http/1.1", "spdy/2");
    SocketChannel socket = serverSocket.accept();
    engine.setUseClientMode(false);
    negotiateHandshake(engine, socket);

    String protocol = engine.getNegotiatedNextProtocol();
    
# Building

mvn package

# Running Tests

Tests require a version of openssl with next protocol negotiation support to be on the PATH. Tests that use openssl will be skipped if it is not found.

# Running JDK Regression Tests

1. Download jtreg: http://openjdk.java.net/jtreg/
2. Edit $JRE/lib/security/java.security Change "com.sun.net.ssl.internal.ssl.Provider" -> "sslnpn.net.ssl.internal.ssl.Provider"
2. jtreg -cpa:target/ssl_npn-0.1-SNAPSHOT.jar jdk_test/ssl

# TODO

1. I think I'm missing a method on the socket and engine interfaces to control bailing connections in the handshake when the client sends a next
protocol that the server doesn't understand. The server can always close the connection after the handshake but this might not be appropriate. For
example if someone npns http/1.1 and then does a POST request they may not know whether the server processed the request if it just closes the socket
after realising it doesn't understand the protocol.
2. API still doesn't feel right. It feels weird having socket.setNextProtocolNegotiationChoices fail if during npn negotiation the protocol can't be selected
   but succeed if no npn negotiation takes place. Also, using setNextProtocolNegotiationFallbackAndChoices it is not possible to know whether the fallback
   has been selected or not. Though, I'm not sure if this is really important.
3. Think about removing handlers that take String and only leave custom byte[] handlers. It is convenient to deal with but it doesn't feel right because US-ASCII maps
   multiple bytes to the same characters.
