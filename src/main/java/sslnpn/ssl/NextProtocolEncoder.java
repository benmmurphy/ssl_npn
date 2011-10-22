package sslnpn.ssl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class NextProtocolEncoder {


	public static byte[] encodeProtocols(byte[]... protocols) {
		try {
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			for (byte[] bytes : protocols) {
				bos.write(bytes.length);
				bos.write(bytes);
			}

			return bos.toByteArray();
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}
	
	
	public static void validateProtocols(byte[]... protocols) {
		if (protocols == null) {
			return;
		}
		
		for (byte[] protocol : protocols) {
			if (protocol.length == 0) {
				throw new IllegalArgumentException("Zero Length Protocol Found");
			}
		}
	}
	
	public static byte[][] encodeProtocols(String... protocols) {
		if (protocols == null) {
			return null;
		}
		
		byte[][] byteProtocols = new byte[protocols.length][];
		for (int i = 0; i < protocols.length; ++i) {
			try {
				byteProtocols[i] = protocols[i].getBytes("US-ASCII");
			} catch (UnsupportedEncodingException e) {
				throw new IllegalStateException(e);
			}
		}
		
		return byteProtocols;
	}

	public static String decodeProtocol(byte[] negotiatedNextProtocol) {
		if (negotiatedNextProtocol == null) {
			return null;
		}
		try {
			return new String(negotiatedNextProtocol, "US-ASCII");
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException(e);
		}
	}


	public static byte[] encodeProtocol(String protocol) {
		try {
			return protocol.getBytes("US-ASCII");
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException(e);
		}
	}


	public static List<byte[]> decodeProtocols(byte[] next_protocol_extension_data) {
        int ptr = 0;

        List<byte[]> protocols = new ArrayList<byte[]>();

        while (ptr < next_protocol_extension_data.length) {
            int len = (next_protocol_extension_data[ptr] & 0xFF);
            if (len == 0) {
                /* not allowed to have zero length protocols */
                return null;
            }
            ptr = ptr + 1;
            if (ptr + len <= next_protocol_extension_data.length) {
                byte[] str = new byte[len];
                System.arraycopy(next_protocol_extension_data, ptr, str, 0, len);
                protocols.add(str);
                ptr = ptr + len;
            } else {
                /* truncated next protocol */
                return null;
            }
        }

        return protocols;
	}
	
	public static List<String> decodeProtocols(List<byte[]> protocols) {
		try {
			List<String> result = new ArrayList<String>(protocols.size());
			for (byte[] protocol : protocols) {
				result.add(new String(protocol, "US-ASCII"));
			}

			return result;
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException(e);
		}
	}
}
