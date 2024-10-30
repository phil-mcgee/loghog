package com.contrastsecurity.agent.loghog.shred;

import com.contrastsecurity.agent.loghog.sql.BatchedSelector;
import org.jooq.impl.DSL;
import java.sql.Connection;
import java.sql.SQLException;

public interface ShredSource {
    String sourceTableName();

    default int batchSize() {
        return 1000;
    };

    default String candidateRowSelectorSql() {
        return DSL.select(DSL.asterisk()).from(sourceTableName()).getSQL();
    };

    default BatchedSelector openCandidateRowSelector(Connection connection) throws SQLException {
        return BatchedSelector.open(connection, candidateRowSelectorSql(), batchSize());
    };

    RowClassifier rowClassifier();
    RowValuesExtractor rowValuesExtractor();


}
