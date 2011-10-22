package sslnpn;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import sslnpn.ssl.NextProtocolEncoder;

public class NextProtocolEncoderTest {

    @Test
    public void testDecode() {
        List<byte[]> protocols = NextProtocolEncoder.decodeProtocols(new byte[]{0x08, 0x68, 0x74,0x74,0x70,0x2f,0x31,0x2e,0x31,0x06,0x73,0x70,0x64,0x79,0x2f,0x32});
        assertEquals(2, protocols.size());
        assertEquals("http/1.1", NextProtocolEncoder.decodeProtocol(protocols.get(0)));
        assertEquals("spdy/2", NextProtocolEncoder.decodeProtocol(protocols.get(1)));

    }
}
