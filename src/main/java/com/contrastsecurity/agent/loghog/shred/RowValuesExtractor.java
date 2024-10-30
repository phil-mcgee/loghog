package com.contrastsecurity.agent.loghog.shred;

import java.util.List;
import java.util.Map;

public interface RowValuesExtractor {
    List<String> extractedValueNames();
    Map<String, Object> extractValues(String patternId, Object[] row);
}
