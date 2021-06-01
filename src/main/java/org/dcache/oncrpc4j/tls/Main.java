package org.dcache.oncrpc4j.tls;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.Security;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;

import com.codahale.metrics.ConsoleReporter;
import com.codahale.metrics.MetricAttribute;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.Timer;
import com.google.common.net.HostAndPort;
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
import java.util.Set;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.TrustManager;

import org.dcache.oncrpc4j.rpc.RpcAuthTypeNone;
import org.dcache.oncrpc4j.rpc.RpcAuthTypeTls;
import org.dcache.oncrpc4j.rpc.RpcAuthTypeUnix;
import org.dcache.oncrpc4j.rpc.RpcCall;
import org.dcache.oncrpc4j.rpc.RpcTransport;
import org.dcache.oncrpc4j.rpc.net.IpProtocolType;
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

  @Option(
      name = "-connect",
      usage = "host/port to connect in the client mode",
      metaVar = "<host:port>")
  private String connect;

  @Option(
      name = "-mode",
      usage = "run in server mode, defaults to \"server\"",
      metaVar = "server|client")
  private String mode = "server";

  public static void main(String[] args) throws Exception {
    new Main().run(args);
  }

  public void run(String[] args) throws Exception {

    CmdLineParser parser = new CmdLineParser(this);
    boolean isServer = true;
    try {
      parser.parseArgument(args);

      if (!List.of("server", "client").contains(mode)) {
        throw new CmdLineException(parser, "Invalid mode: " + mode);
      }

      isServer = mode.equals("server");

      if (help) {
        System.out.println();
        System.out.print("Usage: \n\n   tls4rpc");
        parser.printSingleLineUsage(System.out);
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

    SSLContext sslContext = createSslContext(certFile, keyFile, new char[0], trustedCa);

    final MetricRegistry metrics = new MetricRegistry();
    final ConsoleReporter reporter =
        ConsoleReporter.forRegistry(metrics)
            .convertRatesTo(TimeUnit.SECONDS)
            .convertDurationsTo(TimeUnit.MILLISECONDS)
            .disabledMetricAttributes(
                Set.of(MetricAttribute.M1_RATE, MetricAttribute.M5_RATE, MetricAttribute.M15_RATE))
            .build();
    reporter.start(10, TimeUnit.SECONDS);

    OncRpcSvc svc = null;
    OncRpcSvcBuilder svcBuilder =
        new OncRpcSvcBuilder()
            .withStartTLS()
            .withoutAutoPublish()
            .withTCP()
            .withSameThreadIoStrategy()
            .withSSLContext(sslContext)
            .withServiceName("rpc-over-tls (" + mode + ")");

    try {
      ClassLoader.getSystemResourceAsStream("banner").transferTo(System.out);
      if (isServer) {
        svcBuilder
            .withPort(rpcPort)
            .withRpcService(
                new OncRpcProgram(progNum, progVers), c ->  {
                  metrics.meter("Request Count").mark();
                  c.acceptedReply(0, XdrVoid.XDR_VOID);
                });
      } else {
        svcBuilder.withClientMode();
      }

      svc = svcBuilder.build();

      svc.start();
      if (isServer) {
        System.out.println("Starting on port   : " + svc.getInetSocketAddress(IpProtocolType.TCP));
      }
      System.out.println("Mode               : " + mode);
      System.out.println("RPC program        : " + progNum);
      System.out.println("RPC program version: " + progVers);
      System.out.println("Trusted CA         : " + trustedCa);
      System.out.println("Hostcert           : " + certFile);
      System.out.println("Hostkey            : " + keyFile);

      if (!isServer) {
        HostAndPort hostAndPort = HostAndPort.fromString(connect);
        RpcTransport t =
            svc.connect(new InetSocketAddress(hostAndPort.getHost(), hostAndPort.getPort()));
        var clntCall = new RpcCall(progNum, progVers, new RpcAuthTypeNone(), t);

        // poke server to start tls
        clntCall.call(0, XdrVoid.XDR_VOID, XdrVoid.XDR_VOID, new RpcAuthTypeTls());
        clntCall.getTransport().startTLS();

        while (true) {
          Timer timer = metrics.timer("Requests");
          Timer.Context context = timer.time();
          clntCall.call(0, XdrVoid.XDR_VOID, XdrVoid.XDR_VOID, RpcAuthTypeUnix.ofCurrentUnixUser());
          context.stop();
        }
      }

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
  public static SSLContext createSslContext(
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
