package com.contrastsecurity.agent.loghog.shred.impl;

import com.contrastsecurity.agent.loghog.shred.CandidateRowSelector;
import org.jooq.impl.DSL;

import java.util.Set;

import static com.contrastsecurity.agent.loghog.db.EmbeddedDatabaseFactory.jooq;
import static com.contrastsecurity.agent.loghog.db.LogTable.LOG_TABLE_NAME;

public class TextSignaturesCandidateRowSelector implements CandidateRowSelector {

    final String sourceTableName;
    final Set<String> matchingSignatureAlternatives;
    final String candidateRowSelectorSql;

    public TextSignaturesCandidateRowSelector(final Set<String> matchingSignatureAlternatives) {
        this(LOG_TABLE_NAME, matchingSignatureAlternatives);
    }

    public TextSignaturesCandidateRowSelector(final String sourceTableName, final Set<String> matchingSignatureAlternatives) {
        this.sourceTableName = sourceTableName;
        this.matchingSignatureAlternatives = matchingSignatureAlternatives;
        this.candidateRowSelectorSql = candidateRowSelectorSql(sourceTableName, entryTestSql(matchingSignatureAlternatives));
    }

    Set<String> matchingSignatureAlternatives() {
        return matchingSignatureAlternatives;
    }

    @Override
    public String candidateRowSelectorSql() {
        return candidateRowSelectorSql;
    }

    private static String candidateRowSelectorSql(final String sourceTableName, final String entryTestSql) {
        return jooq().select(DSL.asterisk()).from(sourceTableName).where(entryTestSql).getSQL();
    }

    static String entryTestSql(final Set<String> matchingSignatureAlternatives) {
        final StringBuilder sb = new StringBuilder();
        String conjunction = "";
        // TODO escaping signatures
        for (String signature : matchingSignatureAlternatives) {
            sb.append(conjunction).append("LOG.ENTRY like '%");
            sb.append(signature).append("%'");
            if (conjunction.isEmpty()) {
                conjunction = " OR ";
            }
        }
        return sb.toString();
    }
}
