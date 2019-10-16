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

import java.util.regex.Pattern;

import static org.sonar.skyscanner.java.checks.Entropy.ENTROPY_THRESHOLD;
import static org.sonar.skyscanner.java.checks.Entropy.getShannonEntropy;


@Rule(
        key = "sonar-secrets-java-01",
        name = "Hardcoded Password",
        description = "Hardcoded secrets can be abused to gain unauthorized access and compromise the security perimiter.",
        priority = Priority.BLOCKER,
        tags = {
                "security",
                "skyscanner",
                "vulnerability"
        }
)
public class Passwords extends AbstractBaseCheck {

    private static final Pattern PASSWORD_VARIABLES = Pattern.compile(".*(password|passwd|pwd|LDAPPASS)$", Pattern.CASE_INSENSITIVE);
    private static final Pattern PASSWORD_VALUE = Pattern.compile(".*(ChangeIt|Password1|admin)$", Pattern.CASE_INSENSITIVE);

    protected void validate(Tree tree, String variable, String value) {
        variable = org.sonar.skyscanner.java.checks.Utils.trimQuotes(variable.toLowerCase().trim());
        value = org.sonar.skyscanner.java.checks.Utils.trimQuotes(value);

        if (value.length() > 1 && !value.contains(" ")) {
            if (!variable.equals(value)) {
                if (PASSWORD_VARIABLES.matcher(variable).matches()) {
                    if (PASSWORD_VALUE.matcher(value).matches()) {
                        reportIssue(tree, "Hardcoded secrets can be abused to gain unauthorized access and compromise the security perimeter.");
                    } else {
                        if (getShannonEntropy(value) >= ENTROPY_THRESHOLD) {
                            reportIssue(tree, "High entropy strings are likely cryptographic material. Review manually to ensure private/secret keys are not hardcoded.");
                        }
                    }
                }

            }
        }
    }
}
