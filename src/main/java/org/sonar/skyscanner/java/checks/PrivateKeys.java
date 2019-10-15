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
package org.sonar.skyscanner.java.checks;

import org.sonar.check.Priority;
import org.sonar.check.Rule;
import org.sonar.plugins.java.api.tree.Tree;


@Rule(
    key = "sonar-secrets-java-05",
    name = "Private Keys",
    description = "Private keys exposed in code may lead to impersonation, data falsification and service compromise.",
    priority = Priority.BLOCKER,
    tags = {
        "security",
        "skyscanner",
        "vulnerability"
    }
)
public class PrivateKeys extends AbstractBaseCheck {

    private static final String[] PRIVATE_KEYS = {
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----"
    };

    protected void validate(Tree tree, String variable, String value) {
        value = Utils.trimQuotes(value);

        if (value.length() > 0) {
            for (String key : PRIVATE_KEYS) {
                if (value.contains(key)) {
                    reportIssue(tree, "Private keys exposed in code may lead to impersonation, data falsification and service compromise.");
                    break;    
                }
            }
        }
    }
}
