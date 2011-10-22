package sslnpn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.junit.Before;
import org.junit.Test;

import sslnpn.ssl.NextProtocolNegotiationChooser;
import sslnpn.ssl.SSLEngineImpl;
import sslnpn.ssl.SSLServerSocketImpl;
import sslnpn.ssl.SSLSocketImpl;


public class OpenSSLCompatabilityTest {

	private File sessionFile = null;

	private static final long TIMEOUT = 5000;

	private int nextPort = 8443;

    private SSLContext context;
	
    private static final boolean DEBUG = true;
	@Before
	public void before() throws Exception {
		if (DEBUG) {
		    debug();
		}
	
		
		sessionFile = File.createTempFile("sess", "sess");
		

	}


    private void debug() {
        System.setProperty("javax.net.debug", "all");
    }
	
	public static class SpawnSSLClient implements Callable<String> {

		private File sessionFile;
		private boolean newSession;
		private int port;
		
		public SpawnSSLClient(int port, File sessionFile, boolean newSession) {
			this.sessionFile = sessionFile;
			this.newSession = newSession;
			this.port = port;
		}
		@Override
		public String call() throws Exception {
			List<String> command = new ArrayList<String>(Arrays.<String>asList("openssl", "s_client", "-nextprotoneg", "http/1.0,spdy/2", "-host", "localhost", "-port", "" + port, "-sess_out", sessionFile.getAbsolutePath()));
			
			if (!newSession) {
				if (DEBUG) System.out.println("C>Starting Session");
				command.add("-sess_in");
				command.add(sessionFile.getAbsolutePath());
			}
			Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
			return drain(process, "C>");
		}
		
	}
	
	public static String drain(Process process, String prefix) throws IOException {
		try {
			BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
			try {
				String line;
				StringBuilder builder = new StringBuilder();

				while ((line = bufferedReader.readLine()) != null) {
				    if (OpenSSLCompatabilityTest.DEBUG) {
					    System.out.println(prefix + line);
					}
					builder.append(line);
					builder.append("\n");
				}
				return builder.toString();
			} finally {
				bufferedReader.close();
			}
		} finally {
			process.destroy();
		}
	}
	
	public static class Chooser implements NextProtocolNegotiationChooser {

		@Override
		public String chooseProtocol(List<String> protocols) {
			return "http/1.1";
			
		}
		
	}
	


	

	private void handleClientSocket(SSLServerSocketImpl serverSocket, boolean checkSpdy, boolean newSession) throws Exception {
		Future<String> sslOutput = Executors.newSingleThreadExecutor().submit(new SpawnSSLClient(serverSocket.getLocalPort(), this.sessionFile, newSession));
		
		SSLSocketImpl socket = (SSLSocketImpl)serverSocket.accept();
		socket.startHandshake();
		socket.getOutputStream().write("helloworld\n".getBytes("UTF-8"));
		socket.close();
		
		String output = sslOutput.get(2, TimeUnit.SECONDS);
		
		if (checkSpdy) {
			assertEquals("spdy/2", socket.getNegotiatedNextProtocol());

			assertTrue(output.contains("Next protocol: (1) spdy/2"));
		} else {
		    assertEquals(null, socket.getNegotiatedNextProtocol());
		}
		
		assertTrue(output.contains("helloworld"));
	}
	

    @Test(timeout = TIMEOUT)
	public void testCreateSSLServerSocketWithOpenSSLAndNoSpdy() throws Exception {
        SSLContext context = createContext();
		
		SSLServerSocketFactory factory = context.getServerSocketFactory();
		
		SSLServerSocketImpl serverSocket = (SSLServerSocketImpl)factory.createServerSocket(0);
		serverSocket.setReuseAddress(true);

		try {

			handleClientSocket(serverSocket, false, true);
			handleClientSocket(serverSocket, false, false);
			
			
		} finally {
			serverSocket.close();
		}
	}
	

    @Test(timeout = TIMEOUT)
	public void testCreateSSLServerSocketWithOpenSSLAndResumeAndSpdy() throws Exception {
        SSLContext context = createContext();
		
		SSLServerSocketFactory factory = context.getServerSocketFactory();
		
		SSLServerSocketImpl serverSocket = (SSLServerSocketImpl)factory.createServerSocket(0);
		serverSocket.setReuseAddress(true);
		serverSocket.setAdvertisedNextProtocols("http/1.1", "spdy/2");

		try {

			handleClientSocket(serverSocket, true, true);
			handleClientSocket(serverSocket, true, false);
			
			
		} finally {
			serverSocket.close();
		}
	}

	
    @Test(timeout = TIMEOUT)
	public void testCreateSSLServerSocketWithOpenSSL() throws Exception {

		SSLContext context = createContext();
		
		SSLServerSocketFactory factory = context.getServerSocketFactory();
		
		SSLServerSocketImpl serverSocket = (SSLServerSocketImpl)factory.createServerSocket(0);
		serverSocket.setReuseAddress(true);
		((SSLServerSocketImpl)serverSocket).setAdvertisedNextProtocols("http/1.1", "spdy/2");

		try {
			handleClientSocket(serverSocket, true, true);

			
		} finally {
			serverSocket.close();
		}
		
	}
	
    @Test(timeout = TIMEOUT)
    public void testCreateSSLClientEngineWithOpenSSL() throws Exception {

        try (ProcessAndPort processAndPort = spawnOpensslServer()) {
            Future<String> sslOutput = Executors.newSingleThreadExecutor().submit(new DrainOutput(processAndPort.process));
    
            SSLContext context = createContext();
            
            SocketChannel socket = SocketChannel.open();
            socket.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), processAndPort.port));
            
            SSLEngineImpl engine = (SSLEngineImpl) context.createSSLEngine();

            engine.setNpnChooser(new Chooser());
            
            engine.setUseClientMode(true);
            
            negotiateHandshake(engine, socket);
            processAndPort.process.destroy();
            assertEquals("http/1.1", engine.getNegotiatedNextProtocol());
            assertTrue(sslOutput.get().contains("http/1.1"));


        }  
            
    }
    
    
	@Test(timeout = TIMEOUT)
	public void testCreateSSLServerEngineWithOpenSSL() throws Exception {
		SSLContext context = createContext();

		
		ServerSocketChannel serverSocket = ServerSocketChannel.open();
		serverSocket.bind(new InetSocketAddress(0));
		

		int port = ((InetSocketAddress)serverSocket.getLocalAddress()).getPort();
		
		try {
			SSLEngineImpl engine = (SSLEngineImpl) context.createSSLEngine();
			engine.setAdvertisedNextProtocols("http/1.1", "spdy/2");


			
			Future<String> sslOutput = Executors.newSingleThreadExecutor().submit(new SpawnSSLClient(port, this.sessionFile, true));

			SocketChannel socket = serverSocket.accept();
			
			engine.setUseClientMode(false);
			
	        negotiateHandshake(engine, socket);
			
			assertEquals("spdy/2", engine.getNegotiatedNextProtocol());
			socket.close();
			
			assertTrue(sslOutput.get().contains("spdy/2"));
				
			
		} finally {
			serverSocket.close();
		}
		
	}


    private void negotiateHandshake(SSLEngineImpl engine, SocketChannel socket)
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
	


	
	public static class DrainOutput implements Callable<String> {
		private Process process;
		public DrainOutput(Process is) {
			this.process = is;
		}
		@Override
		public String call() throws Exception {
			String output =  drain(process, "S>");
			return output;
	
		}
	}

	
	static class ProcessAndPort implements AutoCloseable {
	    private Process process;
	    private int port;
	    
	    public ProcessAndPort(Process process, int port) {
	        this.port =  port;
	        this.process = process;
	    }

        @Override
        public void close() throws Exception {
            this.process.destroy();
            
        }
	}
	private ProcessAndPort spawnOpensslServer() throws IOException {
	    int port = nextPort;
	    ++nextPort;
	    
		Process process =  new ProcessBuilder("openssl", "s_server", "-nextprotoneg", "http/1.1,spdy/2", "-debug", "-msg", "-port", "" + port, "-key", "server.key", "-cert", "server.crt").redirectErrorStream(true).start();
		return new ProcessAndPort(process, port);
	}

	
    @Test(timeout = TIMEOUT)
	public void testCreateSSLSocketWithOpensslServerAndNoNpn() throws Exception {
		try (ProcessAndPort sslServer = spawnOpensslServer()) {
    		Future<String> sslOutput = Executors.newSingleThreadExecutor().submit(new DrainOutput(sslServer.process));
    
    		Thread.sleep(1000);
    		
    		SSLContext context = createContext();
    		
    		SSLSocketFactory factory = context.getSocketFactory();
    		
    		SSLSocketImpl socket = (SSLSocketImpl) factory.createSocket();
    		socket.connect(new InetSocketAddress("localhost", sslServer.port));
    		
    		socket.startHandshake();
    		socket.getOutputStream().write("helloworld".getBytes("UTF-8"));
    		assertEquals(null, socket.getNegotiatedNextProtocol());
    		socket.close();
    		Thread.sleep(1000);
    		sslServer.process.destroy();
    		
    		String output = sslOutput.get(2, TimeUnit.SECONDS);
    		
    		assertTrue("Failed to receive helloworld in server output: " + output, output.contains("helloworld"));
		}
		
	}
	
    @Test(timeout = TIMEOUT)
	public void testCreateSSLSocketWithOpensslServerWithResumption() throws Exception {
		try (ProcessAndPort sslServer = spawnOpensslServer()) {
    		Future<String> sslOutput = Executors.newSingleThreadExecutor().submit(new DrainOutput(sslServer.process));
    
    		SSLSocketImpl socket1 = connectToSSLServer(sslServer.port);
    
    		SSLSocketImpl socket2 = connectToSSLServer(sslServer.port);
    
    		assertTrue(Arrays.equals(socket1.getSession().getId(), socket2.getSession().getId()));
    		
    		sslServer.process.destroy();
    
    		String output = sslOutput.get(2, TimeUnit.SECONDS);
    
    		assertTrue("Failed to receive http/1.1 in server output: " + output, output.contains("NEXTPROTO is http/1.1"));
		}

		
	}
    @Test(timeout = TIMEOUT)
	public void testCreateSSLSocketWithOpensslServer() throws Exception {
		try(ProcessAndPort sslServer = spawnOpensslServer()) {
    		Future<String> sslOutput = Executors.newSingleThreadExecutor().submit(new DrainOutput(sslServer.process));
    
    		
    		SSLSocketImpl socket1 = connectToSSLServer(sslServer.port);
    
    
    		
    		sslServer.process.destroy();
    		
    		String output = sslOutput.get(2, TimeUnit.SECONDS);
    		
    		assertTrue("Failed to receive http/1.1 in server output: " + output, output.contains("NEXTPROTO is http/1.1"));
		}

	}
	



	private SSLSocketImpl connectToSSLServer(int port) throws Exception {
		SSLContext context = createContext();
		SSLSocketFactory factory = context.getSocketFactory();
		
		SSLSocketImpl socket = (SSLSocketImpl) factory.createSocket();
		socket.setNpnChooser(new Chooser());
		socket.connect(new InetSocketAddress("localhost", port));
		
		socket.startHandshake();
		socket.getOutputStream().write("hello".getBytes("UTF-8"));
		
		assertEquals("http/1.1", socket.getNegotiatedNextProtocol());

		
		socket.close();
		Thread.sleep(500);
		return socket;
	}
	
	
	private SSLContext createContext() throws KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException, FileNotFoundException, IOException {
	    if (context == null) {
	        context = newContext();
	    }
	    return context;
	    
	}
	private SSLContext newContext() throws NoSuchAlgorithmException,
			KeyManagementException, KeyStoreException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException {
		KeyStore store = KeyStore.getInstance("PKCS12");
		FileInputStream stream = new FileInputStream("server.pkcs12");
		try {
			store.load(stream, "test123".toCharArray());
		} finally {
			stream.close();
		}
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(store, "test123".toCharArray());
		
		SSLContext context = SSLContext.getInstance("TLSv1.2", new sslnpn.net.ssl.internal.ssl.Provider());
		context.init(kmf.getKeyManagers(), new TrustManager[]{new NaiveTrustManager()}, new SecureRandom());
		return context;
	}
}
