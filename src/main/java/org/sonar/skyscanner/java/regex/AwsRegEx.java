package org.sonar.skyscanner.java.regex;

public interface AwsRegEx {
    String[] patterns = {
            ".*(?i)(?:access(?:-|_|)key(?:-id|_id|))\\s*(?:=|\\:|)\\s*[\\\"\\']?([A-Z0-9]{20})[\\'\\\"]?\\s*.{0,256}(?i)(?:secret(?:-|_|)(?:access|)(?:-|_|)key)\\s*(?:=|\\:|)\\s*[\\\"\\']?([A-Za-z0-9\\+\\/]{40})[\\'\\\"]?.*",
            ".*(?i)(?:<access-key>)\\s*(?:=|\\:|)\\s*[\\\"\\']?([A-Z0-9]{20})[\\'\\\"]?\\s*(?i)(?:</access-key>)\\s*.{0,256}(?i)(?:<secret-key>)\\s*(?:=|\\:|)\\s*[\\\"\\']?([A-Za-z0-9\\+\\/]{40})[\\'\\\"]?(?i)\\s*(?:</secret-key>).*",
            ".*curl\\s*-X\\s*PUT\\s*-d\\s*'([A-Z0-9]{20})'\\s*curl\\s*-X\\s*PUT\\s*-d\\s*'([A-Za-z0-9\\+\\/]{40})'.*",
            ".*String\\s*ACCESS_KEY\\s*=\\s*\"([A-Z0-9]{20})\";\\s*String\\s*SECRET_KEY\\s*=\\s*\"([A-Za-z0-9\\+\\/]{40})\";.*"
    };

}

