package sslnpn;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

import sslnpn.ssl.SSLEngineImpl;

public class SSLEngineHandshaker {

    public static void negotiateHandshake(SSLEngineImpl engine, SocketChannel socket)
            throws SSLException, IOException {
        SSLSession session = engine.getSession();
        ByteBuffer myAppData = ByteBuffer.allocate(session
                .getApplicationBufferSize());
        ByteBuffer myNetData = ByteBuffer.allocate(session
                .getPacketBufferSize());
        ByteBuffer peerAppData = ByteBuffer.allocate(session
                .getApplicationBufferSize());
        ByteBuffer peerNetData = ByteBuffer.allocate(session
                .getPacketBufferSize());
        engine.beginHandshake();
        
        while (engine.getHandshakeStatus() != HandshakeStatus.NOT_HANDSHAKING) {
            switch (engine.getHandshakeStatus()) {
            case NEED_TASK:
                engine.getDelegatedTask().run();
                break;
            case NEED_WRAP:
                SSLEngineResult result = engine.wrap(myAppData, myNetData);
                socket.configureBlocking(true);
                
                myNetData.flip();
                socket.write(myNetData);

                myNetData.compact();
                break;
            case NEED_UNWRAP:
                socket.configureBlocking(false);
                socket.read(peerNetData);
                peerNetData.flip();
                result = engine.unwrap(peerNetData, peerAppData);
                peerAppData.rewind();
                peerNetData.compact();
                break;
            }
        }
    }
    

    
}
