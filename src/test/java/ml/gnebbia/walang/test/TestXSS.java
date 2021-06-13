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

public class TestXSS extends WaLangTest {
  private static class XSSModel {
    public final WebServer server = new WebServer("server1");
    public final WebApplication app = new WebApplication("ExampleXSSVulnerableApp");


    public final Endpoint searchEndpoint = new Endpoint("/search.jsp");
    public final InputField iFieldSearch = new InputField("query");

    // Instantiate an Endpoint with a Correctly Sanitized Field
    public final Endpoint contactUsEndpoint = new Endpoint("/search.jsp");
    public final InputField iFieldEmail = new InputField("email",true);


    public XSSModel() {
      server.addWebapplication(app);

      app.addEndpoints(searchEndpoint);
      app.addEndpoints(contactUsEndpoint);

      searchEndpoint.addInputfields(iFieldSearch);
      contactUsEndpoint.addInputfields(iFieldEmail);
    }
  }

  @Test
  public void testFuzzXSS() {
    /*
     * TestFuzzXSS
     * In this case an attacker has direct access to an endpoint
     * discovers one of its input fields, tries to fuzz
     * and can perform XSS with some effort
     */
    
    System.out.println("### Running Test: " + Thread.currentThread().getStackTrace()[1].getMethodName());
    var model = new XSSModel();

    var attacker = new Attacker();
    attacker.addAttackPoint(model.searchEndpoint.access);

    attacker.addAttackPoint(model.iFieldSearch.discover);
    attacker.addAttackPoint(model.iFieldSearch.fuzz);
    attacker.attack();

    model.iFieldSearch.xss.assertCompromisedWithEffort();
  }

  @Test
  public void testFuzzSanitizedInputForXSS() {
    /*
     * TestFuzzSanitizedInputForXSS
     * In this case an attacker has direct access to an endpoint
     * discovers one of its input fields, tries to fuzz
     * but cannot perform XSS because the input is sanitized
     */
    
    System.out.println("### Running Test: " + Thread.currentThread().getStackTrace()[1].getMethodName());
    var model = new XSSModel();

    var attacker = new Attacker();
    attacker.addAttackPoint(model.contactUsEndpoint.access);

    attacker.addAttackPoint(model.iFieldEmail.discover);
    attacker.addAttackPoint(model.iFieldEmail.fuzz);
    attacker.attack();

    model.iFieldEmail.xss.assertUncompromised();
  }

}
