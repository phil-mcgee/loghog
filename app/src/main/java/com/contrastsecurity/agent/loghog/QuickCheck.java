/* (C)2024 */
package com.contrastsecurity.agent.loghog;

import static com.contrastsecurity.agent.loghog.db.LogTable.LOG_TABLE_NAME;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;

public class QuickCheck {
  private static final List<String[]> TELLS =
      Arrays.asList(
          new String[] {
            "MAX_CONTEXT_SOURCE_EVENTS", "Maximum source events reached for this context."
          },
          new String[] {"MAX_CONTEXT_PROPAGATION_EVENTS", "Ignoring propagator "},
          new String[] {"MAX_TRACE_TTL", "Cleared expired assessment context"},
          new String[] {"MAX_TRACE_TTL", "Removing expired key="},
          new String[] {"CONTEXT_MAP_PURGE_TIMEOUT", "Removing long-living runnable"});

  public static void reportTells(Connection connection) throws SQLException {
    StringBuilder qrystr =
        new StringBuilder(
            "SELECT entry \n"
                + "FROM "
                + LOG_TABLE_NAME
                + "\n"
                + "WHERE \n"
                + "    line in (\n"
                + "         SELECT line \n"
                + "         FROM mesg \n"
                + "         WHERE false");

    for (String[] tell : TELLS) {
      qrystr.append("\n\t OR message like '%").append(tell[1]).append("%'");
    }
    qrystr.append(")\nORDER BY line;");

    try (PreparedStatement stmt = connection.prepareStatement(qrystr.toString())) {
      ResultSet rs = stmt.executeQuery();
      rs.last();
      int rowCount = rs.getRow();
      rs.beforeFirst();
      System.out.println("Found " + Math.max(rowCount, 0) + " log entries of concern.");
      while (rs.next()) {
        System.out.println(rs.getString("entry"));
      }
    }
  }

  //    public static void main(String[] args) {
  //        if (args.length < 1) {
  //            throw new IllegalArgumentException("Missing command line parameter for log
  // name.");
  //        }
  //
  //        String logname = args[0];
  //        try {
  //            Connection connection = CreateDb.connectDb(logname);
  //            new MesgShred().createTables(connection);
  //            reportTells(connection);
  //        } catch (SQLException e) {
  //            e.printStackTrace();
  //        }
  //    }
}
