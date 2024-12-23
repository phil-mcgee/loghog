package com.contrastsecurity.agent.loghog.shred;

import org.jooq.impl.DSL;

import static com.contrastsecurity.agent.loghog.db.EmbeddedDatabaseFactory.jooq;
import static com.contrastsecurity.agent.loghog.db.LogTable.LOG_TABLE_NAME;

public interface CandidateRowSelector {
    String candidateRowSelectorSql();

    static CandidateRowSelector allRowsSelector(String sourceTableName) {
        return new CandidateRowSelector() {
            @Override
            public String candidateRowSelectorSql() {
                return jooq().select(DSL.asterisk()).from(LOG_TABLE_NAME).getSQL();
            }
        };
    }
}
