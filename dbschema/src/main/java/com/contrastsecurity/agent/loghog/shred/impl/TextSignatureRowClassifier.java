package com.contrastsecurity.agent.loghog.shred.impl;

import com.contrastsecurity.agent.loghog.shred.PatternSignatures;
import com.contrastsecurity.agent.loghog.shred.RowClassifier;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import static com.contrastsecurity.agent.loghog.shred.impl.BaseShred.LOG_TABLE_ENTRY_IDX;

/**
 * Searches the "value" field of a "sourceRow" for a pattern's text signatures. The value string
 * must contain all signatures to match a pattern and the first matching pattern is returned. So
 * order matters in the PatternSignatures list.
 */
public class TextSignatureRowClassifier implements RowClassifier {

  final List<PatternSignatures> patternsSignatures;

  public TextSignatureRowClassifier(List<PatternSignatures> patternsSignatures) {
    this(patternsSignatures, LOG_TABLE_ENTRY_IDX);
  }

  public TextSignatureRowClassifier(List<PatternSignatures> patternsSignatures, int rowValueIdx) {
    this.patternsSignatures = List.copyOf(patternsSignatures);
  }

  public String findPattern(Object[] sourceRow) {
    return findPattern(sourceRow, Collections.emptySet());
  }

  public String findPattern(Object[] sourceRow, Set<String> excludedPatternIds) {
    final String value = (String) sourceRow[LOG_TABLE_ENTRY_IDX];
    for (PatternSignatures patternSignatures : patternsSignatures) {
      if (!excludedPatternIds.contains(patternSignatures.patternId())
        && signaturesMatch(patternSignatures, value)) {
        return patternSignatures.patternId();
      };
    }
    return MISFIT_PATTERN_ID;
  }

  private static boolean signaturesMatch(PatternSignatures patternSignatures, String value) {
    boolean isMatch = true;
    for (String signature : patternSignatures.signatures()) {
      if (!value.contains(signature)) {
        isMatch = false;
        break;
      }
    }
    return isMatch;
  }

}
