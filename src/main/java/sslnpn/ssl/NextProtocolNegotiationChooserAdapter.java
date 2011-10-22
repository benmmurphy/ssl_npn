package sslnpn.ssl;

import java.util.List;

public class NextProtocolNegotiationChooserAdapter implements NextProtocolNegotiationChooserUsingRawBytes {

	private NextProtocolNegotiationChooser chooser = null;
	
	public NextProtocolNegotiationChooserAdapter(NextProtocolNegotiationChooser chooser) {
		this.chooser = chooser;
	}

	@Override
	public byte[] chooseProtocol(List<byte[]> protocols) {
		List<String> stringProtocols = NextProtocolEncoder.decodeProtocols(protocols);
		String result = this.chooser.chooseProtocol(stringProtocols);
		if (result == null) {
			return null;
		} else {
			return NextProtocolEncoder.encodeProtocol(result);
		}
	}
}
