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

public class TestSQLInjection extends WaLangTest {
  private static class SQLInjectionModel {
    public final WebServer server = new WebServer("server1");
    public final WebApplication app = new WebApplication("ExampleSQLIVulnerableApp");


    public final Endpoint searchEndpoint = new Endpoint("/search.jsp");
    public final InputField iFieldSearch = new InputField("query");


    public SQLInjectionModel() {
      server.addWebapplication(app);
      app.addEndpoints(searchEndpoint);
      searchEndpoint.addInputfields(iFieldSearch);
    }
  }

  @Test
  public void testFuzzSQLInjection() {
    /*
     * TestFuzzSQLInjection
     * In this case an attacker has direct access to an endpoint
     * discovers one of its input fields, tries to fuzz
     * and can perform SQL-Injection with some effort
     */
    
    System.out.println("### Running Test: " + Thread.currentThread().getStackTrace()[1].getMethodName());
    var model = new SQLInjectionModel();

    var attacker = new Attacker();
    attacker.addAttackPoint(model.searchEndpoint.access);

    attacker.addAttackPoint(model.iFieldSearch.discover);
    attacker.addAttackPoint(model.iFieldSearch.fuzz);
    attacker.attack();

    model.iFieldSearch.sqlinjection.assertCompromisedWithEffort();
  }


}
