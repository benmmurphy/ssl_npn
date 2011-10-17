package sslnpn;

import javax.net.ssl.SSLContext;

import org.junit.Test;

public class SSLEngineTest {

	@Test
	public void testCreateSSLEngine() throws Exception {
		
		SSLContext context = SSLContext.getInstance("TLSv1.2", new sslnpn.net.ssl.internal.ssl.Provider());
		System.out.println(context.getProtocol());
	}
}
