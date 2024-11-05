/* (C)2024 */
package com.contrastsecurity.agent.loghog.shred;

import com.contrastsecurity.agent.loghog.sql.BatchedSelector;
import org.jooq.impl.DSL;

import java.sql.Connection;
import java.sql.SQLException;

import static com.contrastsecurity.agent.loghog.db.EmbeddedDatabaseFactory.jooq;

public class ShredSource {
  static final int DEFAULT_BATCH_SIZE = 1000;

  final String sourceTableName;
  final RowValuesExtractor rowValuesExtractor;
  final RowClassifier rowClassifier;
  final int batchSize;

  final String candidateRowSelectorSql;

  public ShredSource(String sourceTableName, RowValuesExtractor rowValuesExtractor) {
    this(
        sourceTableName,
        rowValuesExtractor,
        new AllSameRowClassifier(),
        jooq().select(DSL.asterisk()).from(sourceTableName).getSQL(),
        DEFAULT_BATCH_SIZE);
  }

  public ShredSource(
      String sourceTableName, RowValuesExtractor rowValuesExtractor, RowClassifier rowClassifier) {
    this(
        sourceTableName,
        rowValuesExtractor,
        rowClassifier,
        jooq().select(DSL.asterisk()).from(sourceTableName).getSQL(),
        DEFAULT_BATCH_SIZE);
  }

  public ShredSource(
      String sourceTableName,
      RowValuesExtractor rowValuesExtractor,
      RowClassifier rowClassifier,
      String candidateRowSelectorSql) {
    this(
        sourceTableName,
        rowValuesExtractor,
        rowClassifier,
        candidateRowSelectorSql,
        DEFAULT_BATCH_SIZE);
  }

  public ShredSource(
      String sourceTableName,
      RowValuesExtractor rowValuesExtractor,
      RowClassifier rowClassifier,
      String candidateRowSelectorSql,
      int batchSize) {
    this.sourceTableName = sourceTableName;
    this.rowValuesExtractor = rowValuesExtractor;
    this.rowClassifier = rowClassifier;
    this.candidateRowSelectorSql = candidateRowSelectorSql;
    this.batchSize = batchSize;
  }

  public String sourceTableName() {
    return sourceTableName;
  }

  public RowValuesExtractor rowValuesExtractor() {
    return rowValuesExtractor;
  }

  public RowClassifier rowClassifier() {
    return rowClassifier;
  }

  public int batchSize() {
    return batchSize;
  }

  public BatchedSelector openCandidateRowSelector(Connection connection) throws SQLException {
    return BatchedSelector.open(connection, candidateRowSelectorSql, batchSize);
  }
}
