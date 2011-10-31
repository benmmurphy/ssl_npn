package sslnpn;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;



public class SSLContextCreator {

    public static SSLContext newContext() throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException,
            CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException {
        KeyStore store = KeyStore.getInstance("PKCS12");
        FileInputStream stream = new FileInputStream("server.pkcs12");
        try {
            store.load(stream, "test123".toCharArray());
        } finally {
            stream.close();
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(store, "test123".toCharArray());

        SSLContext context = SSLContext.getInstance("TLSv1.2", new sslnpn.net.ssl.internal.ssl.Provider());
        context.init(kmf.getKeyManagers(), new TrustManager[] { new NaiveTrustManager() }, new SecureRandom());
        return context;
    }
}
