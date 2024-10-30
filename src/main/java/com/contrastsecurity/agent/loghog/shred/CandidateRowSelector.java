package com.contrastsecurity.agent.loghog.shred;

import java.sql.Connection;
import java.util.List;

public interface CandidateRowSelector {

    boolean selectBatch(Connection connection, int batchSize, List<Object[]> candidateRows);
}
