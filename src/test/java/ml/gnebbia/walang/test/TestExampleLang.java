/*
 * Copyright 2020 Foreseeti AB
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

public class TestExampleLang extends ExampleLangTest {
  private static class ExampleLangModel {
    public final WebServer server = new WebServer("gnebbia.ml");
    public final WebApplication app = new WebApplication("personalwebsite");

    public final AdminArea admin_area = new AdminArea("adminarea1");

    public final Administrator admin1 = new Administrator("admin1");
    public final Password admin1pass = new Password("password123");

    public final User user2 = new User("andrea");
    public final Password user2pass = new Password("p4ssw0rd");

    public ExampleLangModel() {
      server.addWebapplication(app);
      app.addAdminarea(admin_area);
      admin_area.addAdministrators(admin1);
      admin1.addTokens(admin1pass);
    }
  }

  @Test
  public void testAccess() {
    var model = new ExampleLangModel();

    var attacker = new Attacker();
    attacker.addAttackPoint(model.admin_area.access);

    attacker.addAttackPoint(model.admin1pass.obtain);
    attacker.attack();

    //model.server.access.assertCompromisedWithEffort();
    model.admin_area.access.assertCompromisedInstantaneously();
  }

  @Test
  public void testNoPassword() {
    var model = new ExampleLangModel();

    var attacker = new Attacker();
    attacker.addAttackPoint(model.admin_area.discover);
    attacker.attack();

    model.admin_area.access.assertUncompromised();
  }

}

// [ERROR] /home/giuseppe/mal/walang/src/test/java/ml/gnebbia/walang/test/TestExampleLang.java:[53,16] error: cannot find symbol
// [ERROR]   symbol:   variable access
// [ERROR]   location: variable server of type WebServer
// [ERROR] /home/giuseppe/mal/walang/src/test/java/ml/gnebbia/walang/test/TestExampleLang.java:[61,33] error: cannot find symbol
// [ERROR]   symbol:   variable adminarea
// [ERROR]   location: variable model of type ExampleLangModel
// [ERROR] /home/giuseppe/mal/walang/src/test/java/ml/gnebbia/walang/test/TestExampleLang.java:[64,16] error: cannot find symbol
// [ERROR]   symbol:   variable access
// [ERROR]   location: variable server of type WebServer
// [ERROR] -> [Help 1]
// [ERROR]
