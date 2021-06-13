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

public class TestCrawling extends WaLangTest {
  private static class CrawlingModel {
    public final WebServer server = new WebServer("server1");
    public final WebApplication app = new WebApplication("ExampleCrawlingVulnerableApp");

    
    // The endpoint search.jsp is linked within the web application 
    public final LinkedEndpoint searchEndpoint = new LinkedEndpoint("/search.jsp");

    // The following endpoints are NOT linked within the web application
    public final HiddenEndpoint adminEndpoint = new HiddenEndpoint("/admin.jsp");
    public final HiddenEndpoint robotsEndpoint = new HiddenEndpoint("/robots.txt");

    // The following endpoint is NOT linked within the web application and corresponds to a private resource for a specific logged-on account
    public final Account account1 = new Account("User123");
    public final Password passAccount1 = new Password("1qaz2wsx");

    boolean accessControlEnforced = true;
    // Correctly configured access control mechanism on the following resource
    public final PrivateEndpoint userPrivateHome = new PrivateEndpoint("/user/123/home.jsp", accessControlEnforced);

    // A misconfigured access control mechanism on the following resource
    public final PrivateEndpoint userPrivateInfo = new PrivateEndpoint("/user/123/details.jsp", !accessControlEnforced);



    public CrawlingModel() {
      server.addWebapplication(app);

      app.addEndpoints(searchEndpoint);
      app.addEndpoints(adminEndpoint);
      app.addEndpoints(robotsEndpoint);
      app.addEndpoints(userPrivateInfo);
      app.addEndpoints(userPrivateHome);

      app.addAccounts(account1);
      account1.addTokens(passAccount1);

      account1.addPrivateurls(userPrivateHome);
      account1.addPrivateurls(userPrivateInfo);
    }
  }

  @Test
  public void testSuccessfulCrawling() {
    /*
     * TestSuccessfulCrawling
     * In this case an attacker tries to crawl a Web Application
     * and istantaneously discovers a linked resource
     */
    
    System.out.println("### Running Test: " + Thread.currentThread().getStackTrace()[1].getMethodName());
    var model = new CrawlingModel();

    var attacker = new Attacker();
    attacker.addAttackPoint(model.app.crawl);

    attacker.attack();

    model.searchEndpoint.discover.assertCompromisedInstantaneously();
  }

  @Test
  public void testFailedCrawling() {
    /*
     * TestFailedCrawling
     * In this case an attacker tries to crawl a Web Application
     * and cannot find a hidden resource
     */
    
    System.out.println("### Running Test: " + Thread.currentThread().getStackTrace()[1].getMethodName());
    var model = new CrawlingModel();

    var attacker = new Attacker();
    attacker.addAttackPoint(model.app.crawl);

    attacker.attack();

    model.adminEndpoint.access.assertUncompromised();
  }

  @Test
  public void testDirectoryBruteForce() {
    /*
     * TestDirectoryBruteForce
     * In this case an attacker tries to bruteforce a web application
     * and with some effort discovers a hidden endpoint
     */
    
    System.out.println("### Running Test: " + Thread.currentThread().getStackTrace()[1].getMethodName());
    var model = new CrawlingModel();

    var attacker = new Attacker();
    attacker.addAttackPoint(model.app.directoryBruteForce);

    attacker.attack();

    model.adminEndpoint.discover.assertCompromisedWithEffort();
  }

  @Test
  public void testIDOR() {
    /*
     * TestIDOR
     * In this case an attacker tries to bruteforce a web application
     * and with some effort discovers a hidden endpoint and is able
     * to access the resource due to misconfigured access control mechanisms
     */
    
    System.out.println("### Running Test: " + Thread.currentThread().getStackTrace()[1].getMethodName());
    var model = new CrawlingModel();

    var attacker = new Attacker();
    attacker.addAttackPoint(model.app.directoryBruteForce);

    attacker.attack();

    model.userPrivateInfo.attemptAccess.assertCompromisedWithEffort();
  }

  @Test
  public void testIDORPrevented() {
    /*
     * TestIDORPrevented
     * In this case an attacker tries to bruteforce a web application
     * and with some effort discovers a hidden endpoint but is not able to access
     * it due to correct authorization mechanisms enforced
     */
    
    System.out.println("### Running Test: " + Thread.currentThread().getStackTrace()[1].getMethodName());
    var model = new CrawlingModel();

    var attacker = new Attacker();
    attacker.addAttackPoint(model.app.directoryBruteForce);

    attacker.attack();

    model.userPrivateHome.attemptAccess.assertCompromisedWithEffort();
  }

}
