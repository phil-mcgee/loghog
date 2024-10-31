/* (C)2024 */
package com.contrastsecurity.agent.loghog.db;

import java.sql.Connection;
import java.sql.SQLException;
import org.jooq.DSLContext;
import org.jooq.SQLDialect;
import org.jooq.impl.DefaultConfiguration;

public class EmbeddedDatabaseFactory {
  public static Connection create(final String databaseFilepath) throws SQLException {
    return H2Database.openDatabase(databaseFilepath);
  }

  public static final String DB_FILE_EXTENSION = ".mv.db";

  public static final SQLDialect DIALECT = SQLDialect.H2;

  public static DSLContext jooq() {
    return new DefaultConfiguration().set(DIALECT).dsl();
  }
}
