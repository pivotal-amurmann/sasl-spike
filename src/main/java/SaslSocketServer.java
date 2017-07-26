import java.net.*;
import java.io.*;
import java.util.Arrays;
import java.util.Collections;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthenticationException;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslServer;

import org.codehaus.groovy.runtime.powerassert.SourceText;
import sun.security.util.Password;

public class SaslSocketServer {
  public static void main(String[] args) throws IOException {
    int portNumber = 3000;

    ServerSocket serverSocket = new ServerSocket(portNumber);
    Socket clientSocket = serverSocket.accept();

    try {
      UserInfo userInfo = new UserInfo();
      PrintWriter out =
          new PrintWriter(clientSocket.getOutputStream(), true);
      BufferedReader in = new BufferedReader(
          new InputStreamReader(clientSocket.getInputStream()));

      SaslServer saslServer = Sasl.createSaslServer("CRAM-MD5", "geode", "localhost",
          Collections.emptyMap(), new ServerCallbackHandler(userInfo));


      String inputLine;

      System.out.println("ready to listen");
      System.out.flush();
      while ((inputLine = in.readLine()) != null) {

        if (saslServer == null) {
          throw new RuntimeException();
        }
        if (saslServer.isComplete()) {
          System.out.println("COMPLETE!");
          return;
        } else {
          byte[] challenge;
          System.out.println("received: " + inputLine);

          if (inputLine.startsWith("start")) {
            challenge = saslServer.evaluateResponse(new byte[0]);
          } else {
            challenge = saslServer.evaluateResponse(inputLine.getBytes());
          }

          out.println(challenge);
        }
      }
    } catch (Exception e)
    {
      System.out.println("Exception caught when trying to listen on port "
          + portNumber + " or listening for a connection");
      System.out.println(e.getMessage());
      e.printStackTrace();
    } finally {
      serverSocket.close();
      clientSocket.close();
    }
  }

  static class ServerCallbackHandler implements CallbackHandler {
    UserInfo userInfo;
    public ServerCallbackHandler(UserInfo userInfo) {
      this.userInfo = userInfo;
    }

    @Override
    public void handle(Callback[] callbacks)
        throws IOException, UnsupportedCallbackException {
      for (int i = 0; i < callbacks.length; i++) {
        System.out.println("ServerCallbackHandler processing callback " + callbacks[i]);

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
              System.out.println("unsupported");
              throw new IOException("Unsupported message type: " +
                  toc.getMessageType());
          }

        } else if (callbacks[i] instanceof NameCallback) {
          NameCallback nameCallback = (NameCallback) callbacks[i];
          this.userInfo.setUsername(nameCallback.getDefaultName());
        } else if (callbacks[i] instanceof PasswordCallback) {
          PasswordCallback passwordCallback = (PasswordCallback) callbacks[i];
          System.out.println("BEFORE username="+userInfo.getUsername() + "; password="+userInfo.getPassword().length);
          this.userInfo.setPassword(passwordCallback.getPassword());
          System.out.println("AFTER username="+userInfo.getUsername() + "; password="+userInfo.getPassword().length);
        } else {
          System.out.println("unsupported: " + callbacks[i]);
          throw new UnsupportedCallbackException
              (callbacks[i], "Unrecognized Callback");
        }
      }

      System.out.println("END username="+userInfo.getUsername() + "; password="+userInfo.getPassword().length);

      if (userInfo.getPassword().equals("secretsecret") && userInfo.getUsername().equals("user")) {
        System.out.println("Authenticated");
      } else {
        System.out.println("NOT Authenticated");
//        throw new AuthenticationException();
      }
    }
  }

  static class UserInfo {
    char[] password = new char[0];
    String username = "";

    public String getUsername() {
      return username == null? "" : username;
    }

    public void setUsername(String username) {
      this.username = username;
    }

    public char[] getPassword() {
      return password==null? new char[0] : password;
    }

    public void setPassword(char[] password) {
      this.password = password;
    }
  }
}