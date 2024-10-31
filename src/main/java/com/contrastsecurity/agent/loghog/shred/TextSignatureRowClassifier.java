package com.contrastsecurity.agent.loghog.shred;

import static com.contrastsecurity.agent.loghog.shred.BaseShred.LOG_TABLE_ENTRY_IDX;

import java.util.List;

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

  public String identifyPattern(Object[] sourceRow) {
    final String value = (String) sourceRow[LOG_TABLE_ENTRY_IDX];
    for (PatternSignatures patternSignatures : patternsSignatures) {
      final String patternId = patternSignatures.patternId();
      boolean isType = true;
      for (String signature : patternSignatures.signatures()) {
        if (!value.contains(signature)) {
          isType = false;
          break;
        }
      }
      if (isType) {
        return patternId;
      }
    }
    return MISFIT_PATTERN_ID;
  }
}
