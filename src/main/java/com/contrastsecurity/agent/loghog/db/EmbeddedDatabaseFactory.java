/* (C)2024 */
package com.contrastsecurity.agent.loghog.db;

import java.sql.Connection;
import java.sql.SQLException;

public class EmbeddedDatabaseFactory {
  public static Connection create(final String databaseFilepath) throws SQLException {
    return H2Database.openDatabase(databaseFilepath);
  }

  //        return DriverManager.getConnection("jdbc:sqlite:" + dbPath);

}
