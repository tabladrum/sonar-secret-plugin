/*
 * Copyright 2018 Skyscanner Limited.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software  * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and  * limitations under the License.
 */
package org.sonar.skyscanner.java;


import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.skyscanner.java.checks.APIKeys;
import org.sonar.skyscanner.java.checks.AWSCredentials;
import org.sonar.skyscanner.java.checks.HighEntropy;
import org.sonar.skyscanner.java.checks.Passwords;
import org.sonar.skyscanner.java.checks.PrivateKeys;
import org.sonar.skyscanner.java.checks.UserNames;

import java.util.ArrayList;
import java.util.List;


final class RulesList {

  private RulesList() {
  }

  public static List<Class<? extends JavaCheck>> getChecks() {
    return getJavaChecks();
  }

  public static List<Class<? extends JavaCheck>> getJavaChecks() {
    List<Class<? extends JavaCheck>> checks = new ArrayList();

    checks.add(Passwords.class);
    checks.add(HighEntropy.class);
    checks.add(AWSCredentials.class);
    checks .add(APIKeys.class);
    checks .add(PrivateKeys.class);
    checks.add(UserNames.class);
    return checks;
  }

  public static List<Class<? extends JavaCheck>> getJavaTestChecks() {
    return  new ArrayList();
  }
}
