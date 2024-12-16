/* (C)2024 */
package com.contrastsecurity.agent.loghog.shred.impl;

import com.contrastsecurity.agent.loghog.shred.CandidateRowSelector;
import com.contrastsecurity.agent.loghog.shred.RowClassifier;
import com.contrastsecurity.agent.loghog.shred.RowValuesExtractor;
import com.contrastsecurity.agent.loghog.shred.ShredSource;
import com.contrastsecurity.agent.loghog.sql.BatchedSelector;

import java.sql.Connection;
import java.sql.SQLException;

public class BaseShredSource implements ShredSource {
  static final int DEFAULT_BATCH_SIZE = 1000;

  final String sourceTableName;
  final RowValuesExtractor rowValuesExtractor;
  final RowClassifier rowClassifier;
  final CandidateRowSelector candidateRowSelector;

  final int batchSize = DEFAULT_BATCH_SIZE;

  public BaseShredSource(
          final String sourceTableName,
          final RowValuesExtractor rowValuesExtractor,
          final RowClassifier rowClassifier,
          final String candidateRowSelectorSql) {
    this(sourceTableName, rowValuesExtractor, rowClassifier,
    new SqlWrapperCandidateRowSelector(candidateRowSelectorSql));
  }

  public BaseShredSource(
      final String sourceTableName,
      final RowValuesExtractor rowValuesExtractor,
      final RowClassifier rowClassifier,
      final CandidateRowSelector candidateRowSelector) {
    this.sourceTableName = sourceTableName;
    this.rowValuesExtractor = rowValuesExtractor;
    this.rowClassifier = rowClassifier;
    this.candidateRowSelector = candidateRowSelector;
  }

  public BaseShredSource(
      String sourceTableName,
      final CandidateRowSelector candidateRowSelector,
      final RowClassifier rowClassifier,
      final RowValuesExtractor rowValuesExtractor
  ) {
    this.sourceTableName = sourceTableName;
    this.rowValuesExtractor = rowValuesExtractor;
    this.rowClassifier = rowClassifier;
    this.candidateRowSelector = candidateRowSelector;
  }

  public BaseShredSource(final BaseShredSource source,
                                 final RowValuesExtractor rowValuesExtractor) {
    this.sourceTableName = source.sourceTableName;
     this.rowClassifier = source.rowClassifier;
    this.candidateRowSelector = source.candidateRowSelector;

    this.rowValuesExtractor = rowValuesExtractor;
  }

  @Override
  public String sourceTableName() {
    return sourceTableName;
  }

  @Override
  public RowValuesExtractor rowValuesExtractor() {
    return rowValuesExtractor;
  }

  @Override
  public RowClassifier rowClassifier() {
    return rowClassifier;
  }

  @Override
  public int batchSize() {
    return batchSize;
  }

  @Override
  public BatchedSelector openCandidateRowSelector(Connection connection) throws SQLException {
    return BatchedSelector.open(connection, candidateRowSelector.candidateRowSelectorSql(), batchSize);
  }

  @Override
  public CandidateRowSelector candidateRowSelector() {
    return candidateRowSelector;
  }
}
