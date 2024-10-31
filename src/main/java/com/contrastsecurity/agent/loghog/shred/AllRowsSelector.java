package com.contrastsecurity.agent.loghog.shred;

import java.sql.Connection;
import java.util.List;

public class AllRowsSelector implements CandidateRowSelector {
    @Override
    public boolean selectBatch(Connection connection, int batchSize, List<Object[]> candidateRows) {
        return false;
    }
}
