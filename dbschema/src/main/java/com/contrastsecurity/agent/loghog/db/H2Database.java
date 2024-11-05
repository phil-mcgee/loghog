/* (C)2024 */
package com.contrastsecurity.agent.loghog.db;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class H2Database {

  public static Connection openDatabase(final String storagePath) throws SQLException {
    // TODO verify storagePath is a writable disk directory path
    // URL of the H2 database
    String jdbcUrl = "jdbc:h2:" + storagePath;

    // TODO Who cares?
    String username = "";
    String password = "";

    Connection connection = null;

    // connect
    connection = DriverManager.getConnection(jdbcUrl, username, password);

    return connection;
  }

  public static void closeDatabase(final Connection connection) {
    closeDatabase(connection, null, null);
  }

  public static void closeDatabase(final Connection connection, final Statement statement) {
    closeDatabase(connection, statement, null);
  }

  public static void closeDatabase(
      final Connection connection, final Statement statement, final ResultSet resultSet) {
    try {
      if (resultSet != null) resultSet.close();
      if (statement != null) statement.close();
      if (connection != null) connection.close();
    } catch (SQLException e) {
      e.printStackTrace();
    }
  }

  public static void closeResultSet(final ResultSet resultSet) throws SQLException {
    if (resultSet != null) resultSet.close();
  }

  public static void closeStatement(final Statement statement) throws SQLException {
    if (statement != null) statement.close();
  }
}
