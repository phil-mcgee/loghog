package com.contrastsecurity.agent.loghog.shred;

/**
 * Searches the "value" field of a "sourceRow" for a pattern's text signatures. The value string
 * must contain all signatures to match a pattern and the first matching pattern is returned. So
 * order matters in the PatternSignatures list.
 */
public class AllSameRowClassifier implements com.contrastsecurity.agent.loghog.shred.RowClassifier {
  public String findPattern(Object[] sourceRow) {
    return ANY_PATTERN_ID;
  }
}
