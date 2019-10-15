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


@Rule(
    key = "sonar-secrets-java-04",
    name = "Hardcoded API Keys",
    description = "Hardcoded API keys can be abused to gain unauthorized access to private services.",
    priority = Priority.CRITICAL,
    tags = {
        "security",
        "skyscanner",
        "vulnerability"
    }
)
public class APIKeys extends AbstractBaseCheck {

    private static final Pattern API_VARIABLES = Pattern.compile(".*(api|gitlab|github|slack|google)_?(key|token|secret)$", Pattern.CASE_INSENSITIVE);

    protected void validate(Tree tree, String variable, String value) {
        variable = Utils.trimQuotes(variable.toLowerCase().trim());
        value = Utils.trimQuotes(value);

        if (value.length() > 0) {
            if (API_VARIABLES.matcher(variable).matches()) {
                reportIssue(tree, "Hardcoded API keys can be abused to gain unauthorized access to private services.");
            }
        }
    }

}