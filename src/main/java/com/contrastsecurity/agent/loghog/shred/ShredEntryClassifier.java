/* (C)2024 */
package com.contrastsecurity.agent.loghog.shred;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

class ShredEntryClassifier {

    private Map<String, List<String>> patternSignatures;

    /**
     * Always matches DEFAULT_PATTERN_ID
     */
    public ShredEntryClassifier() {
        this(null);
    }

    /**
     * Every string the list must be found in the log line for the pattern
     * to be considered a match.
     * @param patternSignatures
     */
    public ShredEntryClassifier(Map<String, List<String>> patternSignatures) {
        if (patternSignatures == null) {
            this.patternSignatures = new HashMap<>();
            this.patternSignatures.put(DEFAULT_PATTERN_ID, List.of(""));
        } else {
            this.patternSignatures = patternSignatures;
        }
    }

    public String findPattern(String logLine) {
        for (Map.Entry<String, List<String>> patternSignature : patternSignatures.entrySet()) {
            String patternId = patternSignature.getKey();
            List<String> signatures = patternSignature.getValue();
            boolean isType = true;
            for (String signature : signatures) {
                if (!logLine.contains(signature)) {
                    isType = false;
                    break;
                }
            }
            if (isType) {
                return patternId;
            }
        }
        return DEFAULT_PATTERN_ID;
    }

    public static final String DEFAULT_PATTERN_ID = "default";
}
