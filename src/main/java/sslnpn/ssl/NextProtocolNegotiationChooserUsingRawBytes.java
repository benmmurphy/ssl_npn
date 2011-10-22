package sslnpn.ssl;

import java.util.List;

public interface NextProtocolNegotiationChooserUsingRawBytes {

	byte[] chooseProtocol(List<byte[]> extensionData);
}
