/* (C)2024 */
package com.contrastsecurity.agent.loghog.shred.impl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

class ShredValueExtractor {
  private List<String> extractedValNames;
  private Map<String, Pattern> valueExtractors;
  public static final String DEFAULT_PATTERN_ID = "default";

  public ShredValueExtractor(List<String> extractedValNames, Map<String, Pattern> valueExtractors) {
    if (extractedValNames == null) {
      this.extractedValNames = new ArrayList<>();
    } else {
      this.extractedValNames = extractedValNames;
    }
    if (valueExtractors == null) {
      this.valueExtractors = new HashMap<>();
      this.valueExtractors.put(DEFAULT_PATTERN_ID, Pattern.compile(""));
    } else {
      this.valueExtractors = valueExtractors;
    }
  }

  public Map<String, Object> extractValues(String patternId, String entry) {
    Pattern extractor = this.valueExtractors.get(patternId);
    if (extractor != null) {
      Matcher match = extractor.matcher(entry);
      if (match.find()) {
        Map<String, Object> extractedVals = new HashMap<>();
        for (String extractedValName : this.extractedValNames) {
          Object val = match.group(extractedValName);
          extractedVals.put(extractedValName, "null".equals(val) ? null : val);
        }
        return extractedVals;
      }
    }
    return null;
  }

  public int expectedCount() {
    return extractedValNames.size();
  }
}
