/* (C)2024 */
package com.contrastsecurity.agent.loghog.shred.impl;

import com.contrastsecurity.agent.loghog.shred.PatternMetadata;
import com.contrastsecurity.agent.loghog.shred.ShredRowMetaData;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static com.contrastsecurity.agent.loghog.shred.impl.BaseShred.LOG_TABLE_LINE_COL;
import static com.contrastsecurity.agent.loghog.shred.impl.BaseShred.SHRED_TABLE_PATTERN_COL;

public class PatternRowValuesExtractor implements com.contrastsecurity.agent.loghog.shred.RowValuesExtractor {
  private static final int LOG_TABLE_ENTRY_IDX = 1;
  private static final int LOG_TABLE_LINE_IDX = 0;

  final Map<String, Pattern> patternMap;
  final List<String> extractedValNames;
  final int sourceValueIdx;
  final int sourceKeyIdx;

  public static PatternRowValuesExtractor buildFrom(final List<ShredRowMetaData> shredMetaData, final List<PatternMetadata> patternMetaData) {
    final  List<String> extractedValNames =
      shredMetaData.stream()
              .map(srmd -> srmd.extractName())
              .filter(extractName -> extractName != LOG_TABLE_LINE_COL && extractName != SHRED_TABLE_PATTERN_COL)
              .toList();
    final Map<String, Pattern> patternMap = patternMetaData.stream()
            .collect(Collectors.toMap(pmd -> pmd.patternId(), pmd -> pmd.pattern()));
    return new PatternRowValuesExtractor(patternMap, extractedValNames);
  }

  public PatternRowValuesExtractor(
          final Map<String, Pattern> patternMap, final List<String> extractedValNames) {
    this(patternMap, extractedValNames, LOG_TABLE_ENTRY_IDX, LOG_TABLE_LINE_IDX);
  }

  public PatternRowValuesExtractor(
          final Map<String, Pattern> patternMap,
          final List<String> extractedValNames,
      final int sourceValueIdx,
      final int sourceKeyIdx) {
    this.patternMap = Map.copyOf(patternMap);
    this.extractedValNames = List.copyOf(extractedValNames);
    this.sourceValueIdx = sourceValueIdx;
    this.sourceKeyIdx = sourceKeyIdx;
  }

  public PatternRowValuesExtractor(final PatternRowValuesExtractor source, final Function<Pattern,Pattern> patternGroomer) {
     this.sourceKeyIdx = source.sourceKeyIdx;
     this.sourceValueIdx = source.sourceValueIdx;
     this.extractedValNames = List.copyOf(source.extractedValNames);

     // created a new patternMap with groomed patterns
     this.patternMap = new HashMap<>(source.patternMap.size());
     for (final Map.Entry<String, Pattern> mapEntry : source.patternMap.entrySet()) {
       patternMap.put(mapEntry.getKey(), patternGroomer.apply(mapEntry.getValue()));
     }
  }

  @Override
  public List<String> extractedValueNames() {
    return extractedValNames;
  }

  @Override
  public Map<String, Object> extractValues(final String patternId, final Object[] row, final boolean verbose) {
    Pattern extractor = patternMap.get(patternId);
    if (extractor != null) {
      Matcher match = extractor.matcher((String) row[sourceValueIdx]);
      if (match.find()) {
        Map<String, Object> extractedVals = new HashMap<>();
        for (String extractedValName : this.extractedValNames) {
          extractedVals.put(extractedValName, match.group(extractedValName));
        }
        return extractedVals;
      } else if (verbose) {
        System.out.println("PatternRowValuesExtractor found no match for " + row[sourceValueIdx]);
      }
    } else if (verbose) {
      System.out.println("Cannot invoke extractor.matcher because extractor is null for patternId '" + patternId + "'");
    }
    return null;
  }

  @Override
  public int expectedCount() {
    return extractedValNames.size();
  }

  @Override
  public Object sourceRowKey(final Object[] row) {
    return row[sourceKeyIdx];
  }

  public Pattern getPattern(final String patternId) {
    return patternMap.get(patternId);
  }
}
