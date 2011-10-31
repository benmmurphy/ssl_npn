package sslnpn.ssl;

import java.util.List;
import java.util.Arrays;

public class NextProtocolNegotiationChooserWithFallback implements NextProtocolNegotiationChooserUsingRawBytes {

        private byte[][] choices;
        private byte[] fallback;
	
	public NextProtocolNegotiationChooserWithFallback(String fallback, String... choices) {
                if (choices == null) {
                    throw new IllegalArgumentException("choices cannot be null");
                }

                
		this.fallback = fallback == null ? null : NextProtocolEncoder.encodeProtocol(fallback);
                this.choices = NextProtocolEncoder.encodeProtocols(choices);
                
	}

        private boolean contains(List<byte[]> haystack, byte[] needle) {
            for (byte[] item : haystack) {
                if (Arrays.equals(needle, item)) {
                    return true;
                }
            }
            return false;
        }

	@Override
	public byte[] chooseProtocol(List<byte[]> protocols) {
                for (byte[] choice : choices) {
                    if (contains(protocols, choice)) {
                        return choice;
                    }
                }

                return fallback; 
	}
}
