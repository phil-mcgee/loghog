/* (C)2024 */
package com.contrastsecurity.agent.loghog.shred;

import com.contrastsecurity.agent.loghog.sql.BatchedSelector;
import com.contrastsecurity.agent.loghog.sql.CreatableSqlTable;
import org.jooq.DataType;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public abstract class AbstractShred {
    public static final String LOG_TABLE_LINE_COL = "log.col(line)";
    public static final int LOG_TABLE_LINE_IDX = 0;

//    public static final String DEFAULT_TYPE = "default";
    public static final boolean SHOW_PROGRESS = false;
    public static final boolean SHOW_MISFITS = false;
    public static final boolean VERBOSE = true;

    private final CreatableSqlTable shredTable;
    private final CreatableSqlTable misfitsTable;
    private final ShredSource shredSource;


    public AbstractShred(
            CreatableSqlTable shredTable,
            CreatableSqlTable misfitsTable,
            ShredSource shredSource) {
        this.shredTable = shredTable;
        this.misfitsTable = misfitsTable;
        this.shredSource = shredSource;

    }

    abstract Object[] shredRowValues(
            Object[] sourceRow, String patternId, Map<String, Object> extractedVals);

    abstract Object[] misfitsRowValues(Object[] sourceRow, Object lastGoodRowKey);

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
                    System.out.println(
                            "Added " + totalMisfits + " rows to table " + misfitsTable.name());
                } else {
                    System.out.println("Found " + totalMisfits + " misfit rows in source table " + shredSource.sourceTableName());
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
        for (String constraintSql: table.createContraintsSql()) {
            stmt.execute(constraintSql);
        }
        for (String indexSql: table.createIndicesSql()) {
            stmt.execute(indexSql);
        }
    }

    protected AddRowsResult addRows(List<Object[]> sourceRows, Object previousGoodRowKey, Connection connection)
            throws SQLException {
        final List<Object[]> values = new ArrayList<>(sourceRows.size());
        final List<Object[]> misfits;
        if (misfitsTable != null) {
            misfits = new ArrayList<>(sourceRows.size());
        } else {
            misfits = null;
        }

        final RowClassifier rowClassifier = shredSource.rowClassifier();
        final RowValuesExtractor valuesExtractor = shredSource.rowValuesExtractor();

        int nAdded = 0;
        int nMisfits = 0;
        Object lastGoodRowKey = previousGoodRowKey;
        final boolean wasAutoCommit = connection.getAutoCommit();
        try (PreparedStatement insertStmt = connection.prepareStatement(shredTable.insertRowSql());
                PreparedStatement insertMisfitsStmt = misfitsTable != null ?
                        connection.prepareStatement(misfitsTable.insertRowSql()) : null) {
            connection.setAutoCommit(false);

            for (Object[] row : sourceRows) {
                String patternId = rowClassifier.identifyPattern(row);
                Map<String, Object> extractedVals = valuesExtractor.extractValues(patternId, row);
                if (extractedVals != null
                        && extractedVals.size() == valuesExtractor.expectedCount()) {
                    Object[] insertVals = shredRow(row, patternId, extractedVals);
                    values.add(insertVals);
                    lastGoodRowKey = valuesExtractor.sourceRowKey(row);
                    nAdded++;
                } else {
                    if (SHOW_MISFITS) {
                        System.out.println(
                                "Extraction/transformation failed in row " + Arrays.asList(row));
                    }
                    if (misfitsTable != null) {
                        final Object[] misfitVals = this.misfitsRow(row, lastGoodRowKey);
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

        return new AddRowsResult(nAdded, nMisfits, lastGoodLine);
    }

    record AddRowsResult(int numAddedShredRows, int numMisfitRows, Object lastGoodRowKey) {}

    public record ShredRowMetaData(String columnName, DataType<?> jooqDataType, Class<?> javaType, String extractName) {}
}