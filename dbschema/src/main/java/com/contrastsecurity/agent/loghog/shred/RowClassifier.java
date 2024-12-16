/* (C)2024 */
package com.contrastsecurity.agent.loghog.shred;

public interface RowClassifier {
  String MISFIT_PATTERN_ID = "misfit";
  String ANY_PATTERN_ID = "any";

  String findPattern(Object[] sourceRow);

  static RowClassifier allTheSameRowClassifier() {
    return allTheSameRowClassifier(ANY_PATTERN_ID);
  }

  static RowClassifier allTheSameRowClassifier(String patternId) {
    return new RowClassifier() {
      @Override
      public String findPattern(Object[] sourceRow) {
        return patternId;
      }
    };
  }
}
