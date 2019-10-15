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

import static org.sonar.skyscanner.java.checks.Entropy.getShannonEntropy;


@Rule(
    key = "sonar-secrets-java-02",
    name = "High Entropy String",
    description = "High entropy strings are likely cryptographic material. Review manually to ensure private/secret keys are not hardcoded.",
    priority = Priority.MAJOR,
    tags = {
        "security",
        "skyscanner",
        "vulnerability"
    }
)
public class HighEntropy extends AbstractBaseCheck {

    private static final double ENTROPY_THRESHOLD = 5.6; // Shannon Entropy higher than this will be reported

    protected void validate(Tree tree, String variable, String value) {
        value = org.sonar.skyscanner.java.checks.Utils.trimQuotes(value);
        
        if (getShannonEntropy(value) >= ENTROPY_THRESHOLD) {
            reportIssue(tree, "High entropy strings are likely cryptographic material. Review manually to ensure private/secret keys are not hardcoded.");
        }
    }
}
