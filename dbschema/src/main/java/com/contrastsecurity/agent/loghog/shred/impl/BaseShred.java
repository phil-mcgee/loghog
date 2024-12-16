/* (C)2024 */
package com.contrastsecurity.agent.loghog.shred.impl;

import com.contrastsecurity.agent.loghog.shred.PatternMetadata;
import com.contrastsecurity.agent.loghog.shred.ShredRowMetaData;
import com.contrastsecurity.agent.loghog.shred.ShredSource;
import com.contrastsecurity.agent.loghog.shred.pmd.PmdShredSource;
import com.contrastsecurity.agent.loghog.sql.BatchedSelector;
import com.contrastsecurity.agent.loghog.sql.CreatableSqlTable;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TIMESTAMP_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.nullCaptureGroupPattern;
import static com.contrastsecurity.agent.loghog.shred.RowClassifier.MISFIT_PATTERN_ID;

public class BaseShred {
  public static final String LOG_TABLE_LINE_COL = "LOG.col(LINE)";
  public static final String LOG_TABLE_ENTRY_COL = "LOG.col(ENTRY)";
  public static final int LOG_TABLE_LINE_IDX = 0;
  public static final int LOG_TABLE_ENTRY_IDX = 1;
  public static final String LAST_MATCH_KEY = "LAST_MATCH_KEY";
  public static final String SHRED_TABLE_PATTERN_COL = "shred.col(PATTERN)";

  public static final boolean SHOW_PROGRESS = false;
  final boolean showMisfits;
  public static final boolean VERBOSE = true;

  private final CreatableSqlTable shredTable;
  private final CreatableSqlTable misfitsTable;
  private final ShredSource shredSource;
  final List <ShredRowMetaData> shredMetadata;
  final List <ShredRowMetaData> misfitsMetadata;

  public BaseShred(
          final List <ShredRowMetaData> shredMetadata,
          final CreatableSqlTable shredTable,
          final List <ShredRowMetaData> misfitsMetadata,
          final CreatableSqlTable misfitsTable,
          final ShredSource shredSource) {
    this(shredMetadata,shredTable,misfitsMetadata,misfitsTable,shredSource,false);
  }

  public BaseShred(
      final List<ShredRowMetaData> shredMetadata,
      final CreatableSqlTable shredTable,
      final List<ShredRowMetaData> misfitsMetadata,
      final CreatableSqlTable misfitsTable,
      final ShredSource shredSource,
      final boolean showMisfits) {
    this.shredTable = shredTable;
    this.misfitsTable = misfitsTable;
    this.shredMetadata = shredMetadata;
    this.misfitsMetadata = misfitsMetadata;
    this.showMisfits = showMisfits;
    this.shredSource = groomedShredSource(shredSource, shredMetadata);
  }

  public boolean showMisfits() {
    return showMisfits;
  }

  public CreatableSqlTable shredTable() {
    return shredTable;
  }

  public CreatableSqlTable misfitsTable() {
    return misfitsTable;
  }

  public List<ShredRowMetaData> shredMetadata() {
    return shredMetadata;
  }

  public List<ShredRowMetaData> misfitsMetadata() {
    return misfitsMetadata;
  }

  public static ShredSource groomedShredSource(final ShredSource shredSource, List<ShredRowMetaData> shredMetadata) {
    if (shredSource instanceof PmdShredSource) {
      final PmdShredSource pmdShredSource = (PmdShredSource)shredSource;
      return new PmdShredSource(pmdShredSource, new PatternGroomer(requiredCaptureGroupNames(shredMetadata)));
    } else if (shredSource.rowValuesExtractor() instanceof PatternRowValuesExtractor) {
      // automatically appends non-matching groups so all patterns return all group names
      final PatternRowValuesExtractor prvExtractor = (PatternRowValuesExtractor)shredSource.rowValuesExtractor();
      return new BaseShredSource((BaseShredSource)shredSource,
                new PatternRowValuesExtractor(prvExtractor,
                    new PatternGroomer(requiredCaptureGroupNames(shredMetadata))));
    } else {
      return shredSource;
    }
  }

  public ShredSource shredSource() {
    return shredSource;
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
      } else if (LOG_TABLE_ENTRY_COL.equals(metaData.extractName())) {
        val = sourceRow[LOG_TABLE_ENTRY_IDX];
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
    if (misfitsMetadata == null){
      return new Object[0];
    }
    Object[] misfitsRow = new Object[misfitsMetadata.size()];
    int idx = 0;
    for (ShredRowMetaData metaData : misfitsMetadata) {
      if (LOG_TABLE_LINE_COL.equals(metaData.extractName())) {
        misfitsRow[idx++] = sourceRow[LOG_TABLE_LINE_IDX];
      } else if (LOG_TABLE_ENTRY_COL.equals(metaData.extractName())) {
        misfitsRow[idx++] = sourceRow[LOG_TABLE_ENTRY_IDX];
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
        final String patternId = rowClassifier.findPattern(row);
        Map<String, Object> extractedVals =
                MISFIT_PATTERN_ID != patternId ?
                valuesExtractor.extractValues(patternId, row, /* FIXME showMisfits*/ false) : null;
        if (extractedVals != null) {
          if (extractedVals.size() == valuesExtractor.expectedCount()) {
            Object[] insertVals = shredRowValues(row, patternId, extractedVals);
            values.add(insertVals);
            lastGoodRowKey = valuesExtractor.sourceRowKey(row);
            nAdded++;
          } else {
            if (showMisfits) {
              System.out.println("\nExtraction/transformation failed in row " + Arrays.asList(row));
              System.out.println("PatternId " + patternId + " returned extractedVals:\n\t" + extractedVals +
                      "\n\tbut expected size was " + valuesExtractor.expectedCount());
            }
            extractedVals = null;
          }
        } else if (showMisfits) {
            System.out.println("\nExtraction/transformation failed in row " + Arrays.asList(row));
            System.out.println("PatternId " + patternId + " returned null extractedVals");
            if (rowClassifier instanceof TextSignatureRowClassifier) {
              final String alternatePattern = ((TextSignatureRowClassifier) rowClassifier)
                      .findPattern(row, Collections.singleton(patternId));
              if (!MISFIT_PATTERN_ID.equals(alternatePattern)) {
                System.out.println("Consider alternatePattern " + alternatePattern + "?  Maybe reorder or modify signatures?");
              }
            }
        }
        if (extractedVals == null) {
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

  public static class PatternGroomer implements Function<Pattern,Pattern> {

    final List<String> requiredNamedGroups;

    public PatternGroomer(final List<String> requiredNamedGroups) {
      this.requiredNamedGroups = requiredNamedGroups;
    }

    @Override
    public Pattern apply(Pattern pattern) {
      return addRequiredCaptureGroups(pattern);
    }

    private Pattern addRequiredCaptureGroups(final Pattern pattern) {
      final Set<String> patternGroups = pattern.namedGroups().keySet();

      final String initialPatternStr = pattern.pattern();
      final boolean endWithDollar = initialPatternStr.endsWith("$");
      final StringBuilder append = new StringBuilder(
              endWithDollar ?
                      initialPatternStr.substring(0, initialPatternStr.length() - 1) :
                      initialPatternStr);
      requiredNamedGroups.stream().filter(name -> !patternGroups.contains(name))
              .forEach(missingName ->append.append(nullCaptureGroupPattern(missingName)));
      if (endWithDollar) {
        append.append('$');
      }

      final Pattern updatedPattern = Pattern.compile(append.toString());
      if (!updatedPattern.namedGroups().keySet().containsAll(requiredNamedGroups)) {
        throw new IllegalStateException("updatedPattern contains capture groups: " +
                updatedPattern.namedGroups().keySet() + " but requires " + requiredNamedGroups);
      }

      return updatedPattern;
    }
  }

  protected static List<String> requiredCaptureGroupNames(final List<ShredRowMetaData> shredMetadata) {
    return shredMetadata.stream().map(smd -> smd.extractName())
            .filter(groupName -> groupName != LOG_TABLE_LINE_COL
                    && groupName != SHRED_TABLE_PATTERN_COL).toList();
  }

  record AddRowsResult(int numAddedShredRows, int numMisfitRows, Object lastGoodRowKey) {}
}
