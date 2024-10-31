/* (C)2024 */
package com.contrastsecurity.agent.loghog.shred;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class ShredEntrySelector {

    private String selectEntriesSql;
    private int batchSize;

    /**
     * Matches every log line
     */
    public ShredEntrySelector() {
        this(ALL_ENTRIES_SIGNATURE, ALL_ENTRIES_SQL, DEFAULT_BATCH_SIZE);
    }

    public ShredEntrySelector(String entrySignature) {
        this(
                entrySignature,
                "select \"line\", \"entry\" from \"log\" where \"entry\" like '%"
                        + entrySignature
                        + "%'",
                DEFAULT_BATCH_SIZE);
    }

    public ShredEntrySelector(String entrySignature, String selectEntriesSql, int batchSize) {
        if (entrySignature == null) {
            entrySignature = ALL_ENTRIES_SIGNATURE;
        }

        if (selectEntriesSql == null) {
            if (entrySignature == null || entrySignature == ALL_ENTRIES_SIGNATURE) {
                this.selectEntriesSql = ALL_ENTRIES_SQL;
            } else {
                this.selectEntriesSql =
                        "select \"line\", \"entry\" from \"log\" where \"entry\" like '%"
                                + entrySignature
                                + "%'";
            }
        } else {
            this.selectEntriesSql = selectEntriesSql;
        }
        this.batchSize = batchSize;
    }

    // FIXME
    // So this reads the query results into a batch row list and then accumulates all the batch
    // lists
    // into a batches list what is the point of this?  We are holding all the data in memory
    // so what is the point of the batch size?
    public List<List<Object[]>> selectBatches(Connection connection) throws SQLException {
        List<List<Object[]>> batches = new ArrayList<>();
        try (PreparedStatement stmt = connection.prepareStatement(this.selectEntriesSql)) {
            ResultSet rs = stmt.executeQuery();
            while (true) {
                List<Object[]> rows = new ArrayList<>();
                for (int i = 0; i < this.batchSize && rs.next(); i++) {
                    rows.add(new Object[] {rs.getInt("line"), rs.getString("entry")});
                }
                if (rows.isEmpty()) {
                    break;
                }
                batches.add(rows);
            }
        }
        return batches;
    }

    /*
        class FileLineIterator implements Iterator<String>, AutoCloseable {

        private final BufferedReader reader;

        public FileLineIterator(String filename) throws IOException {
            this.reader = new BufferedReader(new FileReader(filename));
        }

        @Override
        public boolean hasNext() {
            try {
                return reader.ready();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String next() {
            try {
                return reader.readLine();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public void close() throws IOException {
            reader.close();
        }
    }
         */
    public static final String ALL_ENTRIES_SIGNATURE = "";
    public static final String ALL_ENTRIES_SQL = "select \"line\", \"entry\" from \"log\"";
    public static final int DEFAULT_BATCH_SIZE = 1000;
}
