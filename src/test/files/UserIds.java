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
class UserIdTestMock {
    private void test_compliant() {
        System.out.println("UserId test"); // Compliant
        var username = "user1";
    }

    private void test_noncompliant() {
        String username = "custom-regex"; // Noncompliant - to test need to put in eid
    }
}
