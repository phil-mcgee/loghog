/* (C)2024 */
package com.contrastsecurity.agent.loghog.db;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class LogDatabaseUtil {
  private static final boolean SHOW_PROGRESS = false;
  private static final int LOG_READ_CHUNK_SIZE = 1000;
  public static final String LOG_TABLE_NAME = "LOG";

  public static void initializeLogTable(Connection connection, String logFilePath)
      throws IOException, SQLException {
    System.out.println("Initializing LOG table from " + logFilePath + " ...");

    // create log table (if necessary)
    createLogTable(connection);

    // fill log table
    int total = 0;
    try (Statement stmt = connection.createStatement()) {
      stmt.execute("DELETE FROM " + LOG_TABLE_NAME);
    }
    try (BufferedReader inlog = new BufferedReader(new FileReader(logFilePath))) {
      final List<String[]> chunk = new ArrayList<>(LOG_READ_CHUNK_SIZE);
      String entry;
      int idx = 0;
      while ((entry = inlog.readLine()) != null) {
        chunk.add(new String[] {String.valueOf(idx + 1), entry});
        if (idx % LOG_READ_CHUNK_SIZE == LOG_READ_CHUNK_SIZE - 1) {
          total += addChunkOfLogEntries(chunk, connection);
          if (SHOW_PROGRESS) {
            System.out.print(".");
          }
          chunk.clear();
        }
        idx++;
      }
      total += addChunkOfLogEntries(chunk, connection);
    }
    if (SHOW_PROGRESS) {
      System.out.println();
    }

    System.out.println("Added " + total + " rows to table " + LOG_TABLE_NAME);
  }

  public static void createLogTable(Connection connection) throws SQLException {
    String sql =
        "CREATE TABLE IF NOT EXISTS "
            + LOG_TABLE_NAME
            + " (LINE INTEGER PRIMARY KEY, ENTRY VARCHAR)";
    try (Statement stmt = connection.createStatement()) {
      stmt.execute(sql);
    }
  }

  public static int addChunkOfLogEntries(List<String[]> chunk, Connection connection)
      throws SQLException {
    String sql = "INSERT INTO " + LOG_TABLE_NAME + " VALUES (?, ?)";
    try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
      connection.setAutoCommit(false);
      for (String[] entry : chunk) {
        pstmt.setInt(1, Integer.parseInt(entry[0]));
        pstmt.setString(2, entry[1]);
        pstmt.addBatch();
      }
      int[] result = pstmt.executeBatch();
      connection.commit();
      return result.length;
    }
  }

  public static String[] classAndPackage(String fqcn) {
    int lastDot = fqcn.lastIndexOf('.');
    String classname = fqcn.substring(lastDot + 1);
    String packageName = fqcn.substring(0, lastDot);
    return new String[] {classname, packageName};
  }

  public static String quotOrNull(String txt) {
    if (txt == null) {
      return "NULL";
    } else {
      return "'" + txt + "'";
    }
  }
}
