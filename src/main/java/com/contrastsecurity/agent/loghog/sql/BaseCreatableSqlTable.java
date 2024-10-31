/* (C)2024 */
package com.contrastsecurity.agent.loghog.sql;

import java.util.List;

public class BaseCreatableSqlTable extends BaseSqlTable implements CreatableSqlTable {

    final String createSql;
    final List<String> createContraintsSql;
    final List<String> createIndicesSql;
    final String insertRowSql;

    public BaseCreatableSqlTable(
            final String name,
            final List<String> columnNames,
            final String createSql,
            final List<String> createContraintsSql,
            final List<String> createIndicesSql,
            final String insertRowSql) {
        super(name, columnNames);
        this.createSql = createSql;
        this.createContraintsSql = List.copyOf(createContraintsSql);
        this.createIndicesSql = List.copyOf(createIndicesSql);
        this.insertRowSql = insertRowSql;
    }

    @Override
    public String createSql() {
        return createSql;
    }

    @Override
    public List<String> createContraintsSql() {
        return createContraintsSql;
    }

    @Override
    public List<String> createIndicesSql() {
        return List.of();
    }

    @Override
    public String insertRowSql() {
        return insertRowSql;
    }
}
