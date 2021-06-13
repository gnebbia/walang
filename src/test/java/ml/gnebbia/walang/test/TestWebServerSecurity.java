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
    public final WebServer fullyPatchedWebServer = new WebServer("secure_server", true);
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
}
