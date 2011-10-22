package sslnpn.ssl;

import java.util.List;

public interface NextProtocolNegotiationChooser {

	String chooseProtocol(List<String> advertisedProtocols);

}
