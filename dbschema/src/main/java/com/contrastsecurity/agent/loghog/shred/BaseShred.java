/* (C)2024 */
package com.contrastsecurity.agent.loghog.shred;

import com.contrastsecurity.agent.loghog.sql.BatchedSelector;
import com.contrastsecurity.agent.loghog.sql.CreatableSqlTable;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;

import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TIMESTAMP_VAR;

public class BaseShred {
  public static final String LOG_TABLE_LINE_COL = "LOG.col(LINE)";
  public static final int LOG_TABLE_LINE_IDX = 0;
  public static final int LOG_TABLE_ENTRY_IDX = 1;
  public static final String LAST_MATCH_KEY = "LAST_MATCH_KEY";
  public static final String SHRED_TABLE_PATTERN_COL = "shred.col(PATTERN)";

  public static final boolean SHOW_PROGRESS = false;
  public static final boolean SHOW_MISFITS = false;
  public static final boolean VERBOSE = true;

  private final CreatableSqlTable shredTable;
  private final CreatableSqlTable misfitsTable;
  private final com.contrastsecurity.agent.loghog.shred.ShredSource shredSource;
  final List <com.contrastsecurity.agent.loghog.shred.ShredRowMetaData> shredMetadata;
  final List <com.contrastsecurity.agent.loghog.shred.ShredRowMetaData> misfitsMetadata;

  public BaseShred(
      final List <com.contrastsecurity.agent.loghog.shred.ShredRowMetaData> shredMetadata,
      final CreatableSqlTable shredTable,
      final List <com.contrastsecurity.agent.loghog.shred.ShredRowMetaData> misfitsMetadata,
      final CreatableSqlTable misfitsTable,
      final com.contrastsecurity.agent.loghog.shred.ShredSource shredSource) {
    this.shredTable = shredTable;
    this.misfitsTable = misfitsTable;
    this.shredSource = shredSource;
    this.shredMetadata = shredMetadata;
    this.misfitsMetadata = misfitsMetadata;
  }

  public Object[] shredRowValues(
      final Object[] sourceRow, final String patternId, final Map<String, Object> extractedVals) {
    Object[] shredRow = new Object[shredMetadata.size()];
    int idx = 0;
    for (com.contrastsecurity.agent.loghog.shred.ShredRowMetaData metaData : shredMetadata) {
      Object val = null;
      if (extractedVals.containsKey(metaData.extractName())) {
        val = extractedVals.get(metaData.extractName());
      } else if (LOG_TABLE_LINE_COL.equals(metaData.extractName())) {
        val = sourceRow[LOG_TABLE_LINE_IDX];
      } else if (SHRED_TABLE_PATTERN_COL.equals(metaData.extractName())) {
        val = patternId;
      }
      if (TIMESTAMP_VAR.equals(metaData.extractName()) && val != null) {
        val = String.valueOf(val).replace(',', '.');
      }
      shredRow[idx++] = val;
    }
    return shredRow;
  }

  public Object[] misfitsRowValues(Object[] sourceRow, Object lastMatchKey) {
    Object[] misfitsRow = new Object[misfitsMetadata.size()];
    int idx = 0;
    for (com.contrastsecurity.agent.loghog.shred.ShredRowMetaData metaData : misfitsMetadata) {
      if (LOG_TABLE_LINE_COL.equals(metaData.extractName())) {
        misfitsRow[idx++] = sourceRow[LOG_TABLE_LINE_IDX];
      } else if (LAST_MATCH_KEY.equals(metaData.extractName())) {
        misfitsRow[idx++] = lastMatchKey;
      }
    }
    return misfitsRow;
  }

  public void createAndPopulateShredTables(final Connection connection) throws SQLException {
    createTables(connection);
    populateShredTables(connection);
  }

  public void createTables(Connection connection) throws SQLException {
    createEmptyTables(connection, shredTable, misfitsTable);
  }

  public void populateShredTables(Connection connection) throws SQLException {
    int totalAdded = 0;
    int totalMisfits = 0;
    Object lastGoodRow = null;
    if (VERBOSE) {
      System.out.println("Shredding to " + shredTable.name() + "...");
    }

    try (final BatchedSelector selector = shredSource.openCandidateRowSelector(connection)) {
      List<Object[]> candidateRows;
      while ((candidateRows = selector.nextBatch()) != null) {
        if (VERBOSE && SHOW_PROGRESS) {
          System.out.print(".");
        }
        AddRowsResult addRowsResult = addRows(candidateRows, lastGoodRow, connection);
        lastGoodRow = addRowsResult.lastGoodRowKey;
        totalAdded += addRowsResult.numAddedShredRows;
        totalMisfits += addRowsResult.numMisfitRows;
        candidateRows.clear();
      }
      if (VERBOSE) {
        if (SHOW_PROGRESS) {
          System.out.println("\n");
        }
        System.out.println("Added " + totalAdded + " rows to table " + shredTable.name());
        if (misfitsTable != null) {
          System.out.println("Added " + totalMisfits + " rows to table " + misfitsTable.name());
        } else {
          System.out.println(
              "Found "
                  + totalMisfits
                  + " misfit rows in source table "
                  + shredSource.sourceTableName());
        }
      }
    }
  }

  // tables must not already exist
  protected void createEmptyTables(
      Connection connection, CreatableSqlTable shredTable, CreatableSqlTable misfitsTable)
      throws SQLException {
    try (Statement stmt = connection.createStatement()) {
      createTable(stmt, shredTable);
      if (misfitsTable != null) {
        createTable(stmt, misfitsTable);
      }
    }
  }

  protected void createTable(final Statement stmt, CreatableSqlTable table) throws SQLException {
    stmt.execute(table.createSql());
    for (String constraintSql : table.createContraintsSql()) {
      stmt.execute(constraintSql);
    }
    for (String indexSql : table.createIndicesSql()) {
      stmt.execute(indexSql);
    }
  }

  protected AddRowsResult addRows(
      List<Object[]> sourceRows, Object previousGoodRowKey, Connection connection)
      throws SQLException {
    final List<Object[]> values = new ArrayList<>(sourceRows.size());
    final List<Object[]> misfits;
    if (misfitsTable != null) {
      misfits = new ArrayList<>(sourceRows.size());
    } else {
      misfits = null;
    }

    final com.contrastsecurity.agent.loghog.shred.RowClassifier rowClassifier = shredSource.rowClassifier();
    final com.contrastsecurity.agent.loghog.shred.RowValuesExtractor valuesExtractor = shredSource.rowValuesExtractor();

    int nAdded = 0;
    int nMisfits = 0;
    Object lastGoodRowKey = previousGoodRowKey;
    final boolean wasAutoCommit = connection.getAutoCommit();
    try (PreparedStatement insertStmt = connection.prepareStatement(shredTable.insertRowSql());
        PreparedStatement insertMisfitsStmt =
            misfitsTable != null
                ? connection.prepareStatement(misfitsTable.insertRowSql())
                : null) {
      connection.setAutoCommit(false);

      for (Object[] row : sourceRows) {
        String patternId = rowClassifier.identifyPattern(row);
        Map<String, Object> extractedVals = valuesExtractor.extractValues(patternId, row);
        if (extractedVals != null && extractedVals.size() == valuesExtractor.expectedCount()) {
          Object[] insertVals = shredRowValues(row, patternId, extractedVals);
          values.add(insertVals);
          lastGoodRowKey = valuesExtractor.sourceRowKey(row);
          nAdded++;
        } else {
          if (SHOW_MISFITS) {
            System.out.println("Extraction/transformation failed in row " + Arrays.asList(row));
          }
          if (misfitsTable != null) {
            final Object[] misfitVals = misfitsRowValues(row, lastGoodRowKey);
            misfits.add(misfitVals);
          }
          nMisfits++;
        }
      }

      // add extracted values to shred table
      for (Object[] value : values) {
        for (int i = 0; i < value.length; i++) {
          insertStmt.setObject(i + 1, value[i]);
        }
        insertStmt.addBatch();
      }
      insertStmt.executeBatch();

      if (misfitsTable != null) {
        // add misfit row to misfits table
        for (Object[] misfit : misfits) {
          for (int i = 0; i < misfit.length; i++) {
            insertMisfitsStmt.setObject(i + 1, misfit[i]);
          }
          insertMisfitsStmt.addBatch();
        }
        insertMisfitsStmt.executeBatch();
      }

      connection.commit();
      connection.setAutoCommit(wasAutoCommit);
    }

    return new AddRowsResult(nAdded, nMisfits, lastGoodRowKey);
  }

  // for debugging

  public static void testPatternMatching(final List<String> exampleLogLines, final List<PatternMetadata> patternMetadataList, final boolean verbose) {
    if (verbose) {
      System.out.println("Patterns:");
      patternMetadataList.stream().map(pmd -> "Pattern " + pmd.patternId() +": " + pmd.pattern()).forEach(System.out::println);
    }
    for (final String example : exampleLogLines) {
      PatternMetadata matchPmd = null;
      System.out.println("\nExample log line: " + example);
      for (final PatternMetadata pmd : patternMetadataList) {
        final Matcher matcher = pmd.pattern().matcher(example);
        if (matcher.matches()) {
          if (matchPmd == null) {
            matchPmd = pmd;
            System.out.println("Found matching pattern (" + pmd.patternId() + "): " + pmd.pattern());
            if (verbose) {
              printExtractedDetail(matcher);
            }
          } else {
            System.out.println("Additional matching pattern (" + pmd.patternId() + "): " + pmd.pattern());
            if (verbose) {
              printExtractedDetail(matcher);
            }          }
        }
      }
      if (matchPmd == null) {
        System.out.println("No matching pattern for log line!");
      }
    }
  }

  public static void printExtractedDetail(Matcher matcher) {
    for (Map.Entry<String, Integer> entry : matcher.namedGroups().entrySet()) {
      final String name = entry.getKey();
      final Integer groupIdx = entry.getValue();
      System.out.println(
              "group("
                      + name
                      + ") -> \'"
                      + String.valueOf(matcher.group(groupIdx))
                      + "\'"
                      + " == null ? "
                      + String.valueOf(matcher.group(name) == null));
    }
  }

  record AddRowsResult(int numAddedShredRows, int numMisfitRows, Object lastGoodRowKey) {}
}
