package com.contrastsecurity.agent.loghog.shred.impl;

import com.contrastsecurity.agent.loghog.shred.CandidateRowSelector;

public class SqlWrapperCandidateRowSelector implements CandidateRowSelector {

    final String candidateRowSelectorSql;

    public SqlWrapperCandidateRowSelector(final String candidateRowSelectorSql) {
        this.candidateRowSelectorSql = candidateRowSelectorSql;
    }

    @Override
    public String candidateRowSelectorSql() {
        return candidateRowSelectorSql;
    }
}
