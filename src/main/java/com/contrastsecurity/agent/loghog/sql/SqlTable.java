/* (C)2024 */
package com.contrastsecurity.agent.loghog.sql;

import java.util.List;

public interface SqlTable {
    String name();

    String createTableSql();

    List<String> indexTableSql();

    String insertRowSql();

    String dropTblSql();
}
