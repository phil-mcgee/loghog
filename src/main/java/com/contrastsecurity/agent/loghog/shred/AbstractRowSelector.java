package com.contrastsecurity.agent.loghog.shred;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public abstract class AbstractRowSelector implements CandidateRowSelector {

    abstract String selectEntriesSql();

    @Override
    public boolean selectBatch(Connection connection, int batchSize, List<Object[]> candidateRows) {
        return false;
    }

    public List<List<Object[]>> selectBatches(Connection connection) throws SQLException {
        List<List<Object[]>> batches = new ArrayList<>();
//        try (PreparedStatement stmt = connection.prepareStatement(selectEntriesSql()) {
//            ResultSet rs = stmt.executeQuery();
//            while (true) {
//                List<Object[]> rows = new ArrayList<>();
//                for (int i = 0; i < this.batchSize && rs.next(); i++) {
//                    rows.add(new Object[] {rs.getInt("line"), rs.getString("entry")});
//                }
//                if (rows.isEmpty()) {
//                    break;
//                }
//                batches.add(rows);
//            }
//        }
        return batches;
    }

    class BatchSelectionState implements AutoCloseable {
        PreparedStatement stmt = null;
        ResultSet rs = null;
    }
}
