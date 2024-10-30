/* (C)2024 */
package com.contrastsecurity.agent.loghog.sql;

import java.util.List;

public interface CreatableSqlTable extends SqlTable {
    String createSql();
    List<String> createContraintsSql();
    List<String> createIndicesSql();
    String insertRowSql();
}
