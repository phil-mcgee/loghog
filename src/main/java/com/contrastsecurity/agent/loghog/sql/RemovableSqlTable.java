/* (C)2024 */
package com.contrastsecurity.agent.loghog.sql;

import java.util.List;

public interface RemovableSqlTable extends CreatableSqlTable {

    String tableDropSql();

    String tableTruncateSql();

    List<String> tableDropContraintsSql();

    List<String> tableDropIndicesSql();

    List<RemovableSqlTable> tablesWithDependentConstraints();
}
