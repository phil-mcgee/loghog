package com.contrastsecurity.agent.loghog.shred;

import com.contrastsecurity.agent.loghog.sql.BatchedSelector;

import java.sql.Connection;
import java.sql.SQLException;

public interface ShredSource {
    String sourceTableName();

    RowValuesExtractor rowValuesExtractor();

    RowClassifier rowClassifier();

    int batchSize();

    BatchedSelector openCandidateRowSelector(Connection connection) throws SQLException;

    CandidateRowSelector candidateRowSelector();
}
