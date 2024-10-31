package com.contrastsecurity.agent.loghog.shred;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PatternRowValuesExtractor implements RowValuesExtractor {
    private static final int LOG_TABLE_ENTRY_IDX = 1;
    private static final int LOG_TABLE_LINE_IDX = 0;

    final Map<String, Pattern> patternMap;
    final List<String> extractedValNames;
    final int sourceValueIdx;
    final int sourceKeyIdx;

    public PatternRowValuesExtractor(Map<String, Pattern> patternMap, List<String> extractedValNames) {
        this(patternMap, extractedValNames, LOG_TABLE_ENTRY_IDX, LOG_TABLE_LINE_IDX);
    }

    public PatternRowValuesExtractor(Map<String, Pattern> patternMap, List<String> extractedValNames, final int sourceValueIdx, final int sourceKeyIdx) {
        this.patternMap = Map.copyOf(patternMap);
        this.extractedValNames = List.copyOf(extractedValNames);
        this.sourceValueIdx = sourceValueIdx;
        this.sourceKeyIdx = sourceKeyIdx;
    }

    @Override
    public List<String> extractedValueNames() {
        return extractedValNames;
    }

    @Override
    public Map<String, Object> extractValues(String patternId, Object[] row) {
        Pattern extractor = patternMap.get(patternId);
        if (extractor != null) {
            Matcher match = extractor.matcher((String)row[sourceValueIdx]);
            if (match.find()) {
                Map<String, Object> extractedVals = new HashMap<>();
                for (String extractedValName : this.extractedValNames) {
                    extractedVals.put(extractedValName, match.group(extractedValName));
                }
                return extractedVals;
            }
        }
        return null;
    }

    @Override
    public int expectedCount() {
        return extractedValNames.size();
    }

    @Override
    public Object sourceRowKey(Object[] row) {
        return row[sourceKeyIdx];
    }

}
