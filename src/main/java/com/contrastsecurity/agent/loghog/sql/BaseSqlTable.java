/* (C)2024 */
package com.contrastsecurity.agent.loghog.sql;

import java.util.List;

public class BaseSqlTable implements SqlTable {

    private final String name;
    private final List<String> columnNames;

    public BaseSqlTable(final String name, final List<String> columnNames) {
        this.name = name;
        this.columnNames = List.copyOf(columnNames);
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public List<String> columnNames() {
        return columnNames;
    }
}
