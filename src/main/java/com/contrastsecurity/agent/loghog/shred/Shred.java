/* (C)2024 */
package com.contrastsecurity.agent.loghog.shred;

import com.contrastsecurity.agent.loghog.sql.SqlTable;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public abstract class Shred {
    public static final String DEFAULT_TYPE = "default";
    public static final boolean SHOW_PROGRESS = false;
    public static final boolean SHOW_MISFITS = false;
    public static final boolean VERBOSE = false;

    private final SqlTable shredTable;
    private final SqlTable shredMisfitsTable;

    private ShredEntrySelector entrySelector;
    private ShredEntryClassifier entryClassifier;
    private ShredValueExtractor valueExtractor;

    //        if (misfitsTblName == null) {
    //            this.misfitsTblName = tblName + "_misfits";
    //        } else {
    //            this.misfitsTblName = misfitsTblName;
    //        }
    //        if (createMisfitsSql == null) {
    //            this.createMisfitsSql = "create table " + this.misfitsTblName + "( line integer
    // primary key references log(line))";
    //        } else {
    //            this.createMisfitsSql = createMisfitsSql;
    //        }

    public Shred(
            SqlTable shredTable,
            SqlTable shredMisfitsTable,
            ShredEntrySelector entrySelector,
            ShredEntryClassifier entryClassifier,
            ShredValueExtractor valueExtractor) {
        this.shredTable = shredTable;
        this.shredMisfitsTable = shredMisfitsTable;
        this.entrySelector = entrySelector;
        this.entryClassifier = entryClassifier;
        this.valueExtractor = valueExtractor;
    }

    public void createTables(Connection connection) throws SQLException {
        createEmptyTables(connection, shredTable, shredMisfitsTable);
        populateShredTables(connection);
    }

    // TODO recreate or keep?
    public static void createEmptyTables(
            Connection connection, SqlTable shredTable, SqlTable shredMisfitsTable)
            throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(shredMisfitsTable.dropTblSql());
            stmt.execute(shredTable.dropTblSql());
            stmt.execute(shredTable.createTableSql());
            stmt.execute(shredMisfitsTable.createTableSql());
            for (String indexSql : shredTable.indexTableSql()) {
                stmt.execute(indexSql);
            }
            for (String indexSql : shredMisfitsTable.indexTableSql()) {
                stmt.execute(indexSql);
            }
        }
    }

    abstract Object[] transformValues(
            int line, String entry, String patternId, Map<String, Object> extractedVals);

    abstract Object[] transformMisfits(int line, int lastGoodLine);

    public void populateShredTables(Connection connection) throws SQLException {
        int totalAdded = 0;
        int totalMisfits = 0;
        int lastGoodLine = -1;
        if (VERBOSE) {
            System.out.println("Shredding to " + shredTable.name() + "...");
        }
        for (List<Object[]> rows : entrySelector.selectBatches(connection)) {
            if (VERBOSE && SHOW_PROGRESS) {
                System.out.print(".");
            }
            int[] results = addRows(rows, lastGoodLine, connection);
            int nAdded = results[0];
            int nMisfits = results[1];
            lastGoodLine = results[2];
            totalAdded += nAdded;
            totalMisfits += nMisfits;
        }
        if (VERBOSE) {
            if (SHOW_PROGRESS) {
                System.out.println("\n");
            }
            System.out.println("Added " + totalAdded + " rows to table " + shredTable.name());
            System.out.println(
                    "Added " + totalMisfits + " rows to table " + shredMisfitsTable.name());
        }
    }

    protected int[] addRows(List<Object[]> logRows, int lastGoodLine, Connection connection)
            throws SQLException {
        List<Object[]> values = new ArrayList<>();
        List<Object[]> misfits = new ArrayList<>();
        int nAdded = 0;
        int nMisfits = 0;

        try (PreparedStatement insertStmt = connection.prepareStatement(shredTable.insertRowSql());
                PreparedStatement insertMisfitsStmt =
                        connection.prepareStatement(shredMisfitsTable.insertRowSql())) {
            connection.setAutoCommit(false);

            for (Object[] row : logRows) {
                int line = (int) row[0];
                String entry = (String) row[1];
                String patternId = entryClassifier.findPattern(entry);
                Map<String, Object> extractedVals = valueExtractor.extractValues(patternId, entry);
                if (extractedVals != null
                        && extractedVals.size() == valueExtractor.expectedCount()) {
                    Object[] insertVals = transformValues(line, entry, patternId, extractedVals);
                    values.add(insertVals);
                    lastGoodLine = line;
                    nAdded++;
                } else {
                    if (SHOW_MISFITS) {
                        System.out.println(
                                "Extraction/transformation failed in entry line "
                                        + line
                                        + ": "
                                        + entry);
                    }
                    Object[] misfitVals = this.transformMisfits(line, lastGoodLine);
                    misfits.add(misfitVals);
                    nMisfits++;
                }
            }

            // add extracted values to shred
            for (Object[] value : values) {
                for (int i = 0; i < value.length; i++) {
                    insertStmt.setObject(i + 1, value[i]);
                }
                insertStmt.addBatch();
            }
            insertStmt.executeBatch();

            // add misfit row to misfits table
            for (Object[] misfit : misfits) {
                for (int i = 0; i < misfit.length; i++) {
                    insertMisfitsStmt.setObject(i + 1, misfit[i]);
                }
                insertMisfitsStmt.addBatch();
            }
            insertMisfitsStmt.executeBatch();

            connection.commit();
        }

        return new int[] {nAdded, nMisfits, lastGoodLine};
    }
}
