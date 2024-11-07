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
            "SELECT LINE, ENTRY \n"
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
    System.out.println("QuickCheck.reportTells() SQL :\n" + qrystr.toString());

    System.out.println("\nLog lines of concern:");
    try (PreparedStatement stmt = connection.prepareStatement(qrystr.toString())) {
      ResultSet rs = stmt.executeQuery();
      while (rs.next()) {
        System.out.println(rs.getInt("LINE") + ": " + rs.getString("ENTRY"));
      }
    }
  }
}
