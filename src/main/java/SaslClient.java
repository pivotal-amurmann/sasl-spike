import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Collections;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.Sasl;

class SaslClient {
  public static void main(String[] args) throws Exception {
    try {
      int portNumber = 3000;
      String hostName = "localhost";
      Socket socket = new Socket(hostName, portNumber);
      System.out.println("connected to socket");
      PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
      OutputStream outputStream = socket.getOutputStream();

      String[] mechanisms = new String[]{"CRAM-MD5"};
      CallbackHandler callbackHandler = new ClientCallbackHandler();
      javax.security.sasl.SaslClient
          saslClient =
          Sasl.createSaslClient(mechanisms, "myId", "geode", "localhost", Collections.emptyMap(),
              callbackHandler);
      out.write("start\n");
      out.flush();
      BufferedReader in = new BufferedReader(
          new InputStreamReader(socket.getInputStream()));
      String readLine;
      while ((readLine = in.readLine()) != null) {
        if (readLine == null) {
          continue;
        }
        byte[] challenge = readLine.getBytes();
        byte[] response = saslClient.evaluateChallenge(challenge);
        outputStream.write(response);
        outputStream.flush();
        if (saslClient.isComplete()) {
          System.out.println("Complete on the client");
          byte[] bytes = readLine.getBytes();
          System.out.println("Received on client: " + saslClient.unwrap(bytes, 0, bytes.length));
          return;
        }
      }
    } catch (Exception ex) {
      System.out.println(ex);
      ex.printStackTrace();
    }
  }

  static class ClientCallbackHandler implements CallbackHandler {
    @Override
    public void handle(Callback[] callbacks)
        throws IOException, UnsupportedCallbackException {
      for (int i = 0; i < callbacks.length; i++) {
        System.out.println("ClientCallbackHandler processing callback " + callbacks[i]);

        if (callbacks[i] instanceof TextOutputCallback) {

          // display the message according to the specified type
          TextOutputCallback toc = (TextOutputCallback) callbacks[i];
          switch (toc.getMessageType()) {
            case TextOutputCallback.INFORMATION:
              System.out.println(toc.getMessage());
              break;
            case TextOutputCallback.ERROR:
              System.out.println("ERROR: " + toc.getMessage());
              break;
            case TextOutputCallback.WARNING:
              System.out.println("WARNING: " + toc.getMessage());
              break;
            default:
              throw new IOException("Unsupported message type: " +
                  toc.getMessageType());
          }

        } else if (callbacks[i] instanceof NameCallback) {
          NameCallback nc = (NameCallback) callbacks[i];

          // ignore the provided defaultName
          nc.setName("user123");

        } else if (callbacks[i] instanceof PasswordCallback) {

          PasswordCallback pc = (PasswordCallback) callbacks[i];
          pc.clearPassword();
          System.out.println("setting password");
          pc.setPassword("secretsecret".toCharArray());
        } else {
          throw new UnsupportedCallbackException
              (callbacks[i], "Unrecognized Callback");
        }
      }
    }
  }
}