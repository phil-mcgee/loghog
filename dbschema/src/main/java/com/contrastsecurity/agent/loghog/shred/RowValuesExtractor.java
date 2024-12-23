/* (C)2024 */
package com.contrastsecurity.agent.loghog.shred;

import java.util.List;
import java.util.Map;

public interface RowValuesExtractor {
  List<String> extractedValueNames();

  Map<String, Object> extractValues(String patternId, Object[] row, boolean verbose);

  int expectedCount();

  Object sourceRowKey(Object[] row);
}
