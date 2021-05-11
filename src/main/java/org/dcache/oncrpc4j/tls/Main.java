package org.dcache.oncrpc4j.tls;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.security.Security;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.dcache.oncrpc4j.rpc.OncRpcProgram;
import org.dcache.oncrpc4j.rpc.OncRpcSvc;
import org.dcache.oncrpc4j.rpc.OncRpcSvcBuilder;

import eu.emi.security.authn.x509.X509CertChainValidatorExt;
import eu.emi.security.authn.x509.helpers.ssl.SSLTrustManager;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.DirectoryCertChainValidator;
import eu.emi.security.authn.x509.impl.PEMCredential;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.util.List;
import javax.net.ssl.TrustManager;

import org.dcache.oncrpc4j.xdr.XdrVoid;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

/** */
public class Main {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  /** Default service certificate file. */
  @Option(name = "-hostcert", usage = "Host certificate", metaVar = "<cert-file>")
  private String certFile = "hostcert.pem";

  /** Default service certificate private key file. */
  @Option(name = "-hostkey", usage = "Host certificate key", metaVar = "<cert-key>")
  private String keyFile = "hostkey.pem";

  /** Default location of trusted ca. */
  @Option(name = "-ca", usage = "chain file with trusted CAs", metaVar = "<ca-chain>")
  public String trustedCa = "ca-chain.pem";

  /** TCP port number. */
  @Option(name = "-port", usage = "TCP port to use", metaVar = "<port>")
  private int rpcPort = 1717;

  /** RPC program number. */
  @Option(name = "-prog", usage = "RPC program number", metaVar = "<prog>")
  private int progNum = 200001;

  /** RPC program version. */
  @Option(name = "-vers", usage = "RPC program version", metaVar = "<vers>")
  private int progVers = 1;

  @Option(name = "-help", usage = "Print help screen")
  private boolean help;

  public static void main(String[] args) throws Exception {
    new Main().run(args);
  }

  public void run(String[] args) throws Exception {

    CmdLineParser parser = new CmdLineParser(this);

    try {
      parser.parseArgument(args);
      if (help) {
        System.out.println();
        System.out.print("Usage: \n\n   tls4rpc"); parser.printSingleLineUsage(System.out);
        System.out.println();
        System.exit(0);
      }
    } catch (CmdLineException e) {
      System.err.println();
      System.err.println(e.getMessage());
      System.err.println("Usage:");
      System.err.println("    tls4rpc [options...]");
      System.err.println();
      parser.printUsage(System.err);
      System.exit(1);
    }

    SSLContext sslContext = buildSSLContext(certFile, keyFile, new char[0], trustedCa);

    OncRpcSvc svc =
        new OncRpcSvcBuilder()
            .withoutAutoPublish()
            .withTCP()
            .withSameThreadIoStrategy()
            .withBindAddress("127.0.0.1")
            .withPort(rpcPort)
            .withSSLContext(sslContext)
            .withStartTLS()
            .withRpcService(
                new OncRpcProgram(progNum, progVers), c -> c.acceptedReply(0, XdrVoid.XDR_VOID))
            .withServiceName("svc")
            .build();

    try {
      ClassLoader.getSystemResourceAsStream("banner").transferTo(System.out);
      System.out.println("Starting on port   : " + rpcPort);
      System.out.println("RPC program        : " + progNum);
      System.out.println("RPC program version: " + progVers);
      System.out.println("Trusted CA         : " + trustedCa);
      System.out.println("Hostcert           : " + certFile);
      System.out.println("Hostkey            : " + keyFile);

      svc.start();
      Thread.currentThread().join();
    } catch (InterruptedException e) {
      System.out.println("Exiting ... ");
    } finally {
      svc.stop();
    }
  }

  /**
   * @param certificateFile certificate file location.
   * @param certificateKeyFile key file location.
   * @param keyPassword password used to protect key file.
   * @param trustStore trusted ca bundle location.
   * @return
   * @throws IllegalArgumentException with provided locations are not absolute.
   * @throws IOException
   * @throws KeyStoreException
   * @throws CertificateException
   */
  public static SSLContext buildSSLContext(
      String certificateFile, String certificateKeyFile, char[] keyPassword, String trustStore)
      throws IOException, GeneralSecurityException {

    // due to bug in canl https://github.com/eu-emi/canl-java/issues/100 enforce absolute path
    if (trustStore.charAt(0) != '/') {
      trustStore = new File(".", trustStore).getAbsolutePath();
    }

    X509CertChainValidatorExt certificateValidator =
        new DirectoryCertChainValidator(
            List.of(trustStore), CertificateUtils.Encoding.PEM, -1, 5000, null);

    PEMCredential serviceCredentials =
        new PEMCredential(certificateKeyFile, certificateFile, keyPassword);

    KeyManager keyManager = serviceCredentials.getKeyManager();
    KeyManager[] kms = new KeyManager[] {keyManager};
    SSLTrustManager tm = new SSLTrustManager(certificateValidator);

    SSLContext sslCtx = SSLContext.getInstance("TLS");
    sslCtx.init(kms, new TrustManager[] {tm}, null);

    return sslCtx;
  }
}
