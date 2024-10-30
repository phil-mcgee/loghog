/* (C)2024 */
package com.contrastsecurity.agent.loghog.sql;

import java.util.List;

public class SqlTableBase implements SqlTable {

    final String name;
    final String createTableSql;
    final List<String> indexTableSql;
    final String insertRowSql;
    final String dropTblSql;

    public SqlTableBase(
            final String name,
            final String createTableSql,
            final List<String> indexTableSql,
            final List<String> columnNames) {
        this(name, createTableSql, indexTableSql, insertSql(name, columnNames));
    }

    public SqlTableBase(
            final String name,
            final String createTableSql,
            final List<String> indexTableSql,
            final String insertRowSql) {
        this.name = name;
        this.createTableSql = createTableSql;
        this.indexTableSql = indexTableSql != null ? indexTableSql : List.of();
        this.insertRowSql = insertRowSql;
        this.dropTblSql = "drop table if exists \"" + name + "\"";
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public String createTableSql() {
        return createTableSql;
    }

    @Override
    public List<String> indexTableSql() {
        return indexTableSql;
    }

    @Override
    public String insertRowSql() {
        return insertRowSql;
    }

    @Override
    public String dropTblSql() {
        return dropTblSql;
    }

    private static String insertSql(final String name, final List<String> insertColumnNames) {
        final StringBuilder sb = new StringBuilder("insert into ");
        sb.append("\"").append(name).append("\"").append(" (");
        String delimiter = "";
        for (final String insertColumnName : insertColumnNames) {
            sb.append(delimiter).append("\"").append(insertColumnName).append("\"");
            delimiter = ", ";
        }
        sb.append(") values (");
        delimiter = "";
        for (final String dontCare : insertColumnNames) {
            sb.append(delimiter).append("?");
            delimiter = ", ";
        }
        return sb.append(")").toString();
    }
}
