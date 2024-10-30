package com.contrastsecurity.agent.loghog.sql;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class BaseSqlTable implements SqlTable {

    private final String name;
    private final List<String> columnNames;
    private final List<Class<?>> columnTypes;

    public BaseSqlTable(final String name, final List<String> columnNames) {
        this(name, columnNames, new ArrayList<>(Collections.nCopies(columnNames.size(), Object.class)));
    }

    public BaseSqlTable(final String name, final List<String> columnNames, List<Class<?>> columnTypes) {
        this.name = name;
        this.columnNames = List.copyOf(columnNames);
        this.columnTypes = List.copyOf(columnTypes);
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public List<String> columnNames() {
        return columnNames;
    }

    public List<Class<?>> columnTypes() {
        return columnTypes;
    }
}
