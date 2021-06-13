/*
 * Copyright 2020 Giuseppe Nebbione
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ml.gnebbia.walang.test;

import core.Attacker;
import org.junit.jupiter.api.Test;

public class TestWebServerSecurity extends WaLangTest {
  private static class WebServerSecurityModel {
    public final WebServer vulnerableWebServer = new WebServer("server1");

    // instantiate a secure webserver
    boolean isFullyPatched= true;
    boolean isEncryptionEnabled = true;
    boolean isXFrameOptionsEnabled = true;
    boolean isSecureFlagEnabled = true;

    public final WebServer fullyPatchedWebServer = new WebServer("secure_server", isFullyPatched, isEncryptionEnabled, isXFrameOptionsEnabled, isSecureFlagEnabled);
    public final WebApplication app = new WebApplication("ExampleWebServerSecurityApp");

    


    public WebServerSecurityModel() {
      vulnerableWebServer.addWebapplication(app);
      fullyPatchedWebServer.addWebapplication(app);

    }
  }

  @Test
  public void testVulnerableWebServerExploitation() {
    /*
     * TestVulnerableWebServerExploitation
     * In this case an attacker is able to exploit an RCE Vulnerability
     * coupled with a privilege escalation weakness and get privileged code
     * execution istantaneously 
     */
    
    System.out.println("### Running Test: " + Thread.currentThread().getStackTrace()[1].getMethodName());
    var model = new WebServerSecurityModel();

    var attacker = new Attacker();
    attacker.addAttackPoint(model.vulnerableWebServer.attemptRCEExploit);
    attacker.addAttackPoint(model.vulnerableWebServer.attemptPrivescExploit);

    attacker.attack();

    model.vulnerableWebServer.privilegedCodeExecution.assertCompromisedInstantaneously();
  }

  @Test
  public void testSecureWebServerExploitation() {
    /*
     * TestSecureWebServerExploitation
     * In this case an attacker is not able to exploit an RCE Vulnerability
     * because the web server is fully patched and updated
     */
    
    System.out.println("### Running Test: " + Thread.currentThread().getStackTrace()[1].getMethodName());
    var model = new WebServerSecurityModel();

    var attacker = new Attacker();
    attacker.addAttackPoint(model.fullyPatchedWebServer.attemptRCEExploit);
    attacker.addAttackPoint(model.fullyPatchedWebServer.attemptPrivescExploit);

    attacker.attack();

    model.fullyPatchedWebServer.privilegedCodeExecution.assertUncompromised();
  }

  @Test
  public void testPlainTextWebServerEavesDrop() {
    /*
     * testPlainTextWebServerEavesDrop
     * In this case an attacker takes advantage of disabled TLS 
     * to intercept communication
     */
    
    System.out.println("### Running Test: " + Thread.currentThread().getStackTrace()[1].getMethodName());
    var model = new WebServerSecurityModel();

    var attacker = new Attacker();
    attacker.addAttackPoint(model.vulnerableWebServer.attemptSniff);

    attacker.attack();

    model.vulnerableWebServer.sniff.assertCompromisedInstantaneously();
  }

  @Test
  public void testTLSEnabledWebServerEavesDrop() {
    /*
     * testTLSEnabledWebServerEavesDrop     
     * In this case an attacker cannot take advantage plaintext
     * to intercept communication, because the webserver has TLS enabled
     */
    
    System.out.println("### Running Test: " + Thread.currentThread().getStackTrace()[1].getMethodName());
    var model = new WebServerSecurityModel();

    var attacker = new Attacker();
    attacker.addAttackPoint(model.fullyPatchedWebServer.attemptSniff);

    attacker.attack();

    model.fullyPatchedWebServer.sniff.assertUncompromised();
  }

  @Test
  public void testClickJackingOnVulnerableWebServer() {
    /*
     * testClickJackingOnSecureWebServer     
     * In this case an attacker successfully takes advantage of a clickjacking 
     * weakness on a vulnerable webserver
     */
    
    System.out.println("### Running Test: " + Thread.currentThread().getStackTrace()[1].getMethodName());
    var model = new WebServerSecurityModel();

    var attacker = new Attacker();
    attacker.addAttackPoint(model.vulnerableWebServer.attemptClickjacking);

    attacker.attack();

    model.vulnerableWebServer.clickjacking.assertCompromisedInstantaneously();
  }

  @Test
  public void testClickJackingOnSecureWebServer() {
    /*
     * testClickJackingOnSecureWebServer     
     * In this case an attacker tries to take advantage of clickjacking on
     * a secure webserver, but fails
     */
    
    System.out.println("### Running Test: " + Thread.currentThread().getStackTrace()[1].getMethodName());
    var model = new WebServerSecurityModel();

    var attacker = new Attacker();
    attacker.addAttackPoint(model.fullyPatchedWebServer.attemptClickjacking);

    attacker.attack();

    model.fullyPatchedWebServer.clickjacking.assertUncompromised();
  }
}
