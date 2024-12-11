package com.contrastsecurity.agent.loghog.logviews;

import com.contrastsecurity.agent.loghog.db.EmbeddedDatabaseFactory;
import org.jooq.DSLContext;
import org.jooq.impl.DSL;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;

public class ViewCreator {

  final static boolean VERBOSE = false;

  final String dbPath;

  public ViewCreator(final String dbPath) {
    this.dbPath = dbPath;
  }

  public void createThreadView() throws SQLException {
    System.out.println("Creating THREAD_VIEW view...");
    try (Connection connect = EmbeddedDatabaseFactory.create(dbPath)) {
      DSLContext jooq = DSL.using(connect);

      final String selectSql = """
SELECT
  thread,
  line,
  timestamp,
  ROW_NUMBER() OVER (PARTITION BY thread ORDER BY line) thread_line,
  LAG(line) OVER (PARTITION BY thread ORDER BY line) prev_in_thread,
  LEAD(line) OVER (PARTITION BY thread ORDER BY line) next_in_thread
FROM mesg
ORDER BY thread, thread_line
""";
      if (VERBOSE) {
        System.out.println("selectSql = \n" + selectSql);
      }

      jooq.createView("THREAD_VIEW").as(selectSql).execute();
      System.out.println("THREAD_VIEW view created.");

      System.out.println("\nCreating a THREAD table from view...");
      final StringBuilder sb = new StringBuilder("create table THREAD (\n");
      // grumble, grumble.  h2 makes this way harder than it should be
      PreparedStatement stmt = connect.prepareStatement("SELECT * FROM THREAD_VIEW LIMIT 0");
      ResultSet rs = stmt.executeQuery();
      ResultSetMetaData rsmd = rs.getMetaData();
      for (int i = 1; i <= rsmd.getColumnCount(); i++) {
        sb.append(rsmd.getColumnName(i)).append(" ");
        final String dataType = rsmd.getColumnTypeName(i);
        sb.append(
                switch (dataType) {
                  case "INTEGER" -> "int";
                  case "CHARACTER VARYING" -> "VARCHAR2";
                  default -> dataType;
                }
        ).append(", \n");
      }
      sb.setLength(sb.length() - ", \n".length());
      sb.append("\n);");

      final String createThreadTableSql = sb.toString();
      if (VERBOSE) {
        System.out.println("createThreadTableSql = \n" + createThreadTableSql);
      }
      stmt.close();

      // create the table
      stmt = connect.prepareStatement(createThreadTableSql);
      stmt.executeUpdate();
      stmt.close();
      System.out.println("THREAD table created.");

      System.out.println("Populating THREAD table...");
      stmt = connect.prepareStatement("INSERT INTO THREAD SELECT * FROM THREAD_VIEW");
      stmt.executeUpdate();
      stmt.close();
    }
    System.out.println("THREAD table populated.");
  }

  public void createRequestView() throws SQLException {
    System.out.println("Creating REQUEST_VIEW view...");
    try (Connection connect = EmbeddedDatabaseFactory.create(dbPath)) {
      DSLContext jooq = DSL.using(connect);
      final String selectSql = """
SELECT
  REQBEG.REQ,
  REQBEG.URL,
  REQBEG.LINE BEGIN_LINE,
  REQBEG.TIMESTAMP BEGIN_TIME,
  REQBEG.THREAD BEGIN_THREAD,
  NEWCTX.LINE CTX_BEG_LINE,
  NEWCTX.ASSESS_CTX,
  FIRSTTRK.LINE TRACE_BEG_LINE,
  FIRSTTRK.TRACE_MAP TRACE_MAP,
  LASTTRK.LINE LAST_TRAK_LINE,
  LASTTRK.THREAD LAST_TRAK_THREAD,
  REQEND.LINE END_LINE,
  REQEND.TIMESTAMP END_TIME,
  REQEND.THREAD END_THREAD
FROM CRUMB REQBEG
JOIN TRAK FIRSTTRK
ON
   REQBEG.PATTERN = 'reqBegin'
   AND FIRSTTRK.LINE IN (
      SELECT min(LINE)
      FROM TRAK
      WHERE
        THREAD = REQBEG.THREAD
        AND LINE > REQBEG.LINE
   )
JOIN TRAK LASTTRK
ON LASTTRK.LINE IN (
    SELECT max(LINE)
    FROM TRAK
    WHERE
      TRACE_MAP = FIRSTTRK.TRACE_MAP
  )
              LEFT JOIN HTTP REQEND
ON
  REQEND.LINE in (
    SELECT max(LINE)
                  FROM HTTP
    WHERE
                    PATTERN = 'reqEnding'
      AND REQ = REQBEG.REQ
  )
LEFT JOIN CTX NEWCTX
  ON
    NEWCTX.LINE IN (
      SELECT min(LINE)
      FROM CTX
      WHERE
        THREAD = REQBEG.THREAD
        AND PATTERN = 'createdAssessCtx'
        AND LINE > REQBEG.LINE
     )
""";
      if (VERBOSE) {
        System.out.println("selectSql = \n" + selectSql);
      }

      jooq.createView("REQUEST_VIEW").as(selectSql).execute();
      System.out.println("REQUEST_VIEW view created.");

      System.out.println("\nCreating a REQUEST table from view...");
      final StringBuilder sb = new StringBuilder("create table REQUEST (\n");
      // grumble, grumble.  h2 makes this way harder than it should be
      PreparedStatement stmt = connect.prepareStatement("SELECT * FROM REQUEST_VIEW LIMIT 0");
      ResultSet rs = stmt.executeQuery();
      ResultSetMetaData rsmd = rs.getMetaData();
      for (int i = 1; i <= rsmd.getColumnCount(); i++) {
        sb.append(rsmd.getColumnName(i)).append(" ");
        final String dataType = rsmd.getColumnTypeName(i);
        sb.append(
                switch (dataType) {
                  case "INTEGER" -> "int";
                  case "CHARACTER VARYING" -> "VARCHAR2";
                  default -> dataType;
                }
        ).append(", \n");
    }
      sb.setLength(sb.length() - ", \n".length());
      sb.append("\n);");

      final String createRequestTableSql = sb.toString();
      if (VERBOSE) {
        System.out.println("createRequestTableSql = \n" + createRequestTableSql);
  }
      stmt.close();

      // create the table
      stmt = connect.prepareStatement(createRequestTableSql);
      stmt.executeUpdate();
      stmt.close();
      System.out.println("REQUEST table created.");

      System.out.println("Populating REQUEST table...");
      stmt = connect.prepareStatement("INSERT INTO REQUEST SELECT * FROM REQUEST_VIEW");
      stmt.executeUpdate();
      stmt.close();
      System.out.println("REQUEST table populated.");
    }
  }


  // NOT CURRENTLY USED
  public void createBadRequestView() throws SQLException {
    System.out.println("Creating BAD_REQUEST view...");
    try (Connection connect = EmbeddedDatabaseFactory.create(dbPath)) {
      DSLContext jooq = DSL.using(connect);
      final String selectSql = """
SELECT *
FROM LOG
WHERE
    LOG.LINE IN (
        SELECT LOG.LINE
        FROM REQUEST BAD_REQ
                 JOIN LOG
                      ON
                          BAD_REQ.END_LINE IS NULL
                              AND (
                              LOG.LINE = BAD_REQ.BEGIN_LINE
                                  OR LOG.LINE = BAD_REQ.CTX_BEG_LINE
                                  OR LOG.LINE = BAD_REQ.TRACE_BEG_LINE
                                  OR LOG.LINE = BAD_REQ.LAST_TRAK_LINE)
        UNION
        SELECT CHG_CTX.LINE
        FROM REQUEST BAD_REQ
                 JOIN CTX CHG_CTX
                      ON
                          BAD_REQ.END_LINE IS NULL
                              AND  CHG_CTX.ASSESS_CTX = BAD_REQ.ASSESS_CTX
                              AND (CHG_CTX.PATTERN = 'savingApp' OR CHG_CTX.PATTERN = 'prepareJump')
        UNION
        SELECT PREVIOUS.LINE
        FROM REQUEST BAD_REQ
                 JOIN CTX SAVE_APP
                      ON
                          BAD_REQ.END_LINE IS NULL
                              AND SAVE_APP.ASSESS_CTX = BAD_REQ.ASSESS_CTX
                              AND SAVE_APP.PATTERN = 'savingApp'
                 JOIN CONT PREVIOUS
                      ON SAVE_APP.LINE = PREVIOUS.LINE
        UNION
        SELECT NEXT_START.LINE FROM
            REQUEST BAD_REQ
                JOIN CTX SAVE_APP
                     ON
                         BAD_REQ.END_LINE IS NULL
                             AND SAVE_APP.ASSESS_CTX = BAD_REQ.ASSESS_CTX
                             AND SAVE_APP.PATTERN = 'savingApp'
                JOIN CONT SAVE_APP_CONT
                     ON SAVE_APP.LINE = SAVE_APP_CONT.LINE
                JOIN MESG APP_SAVE_MESG
                     ON APP_SAVE_MESG.LINE = SAVE_APP_CONT.MESG
                JOIN CTX NEXT_START
                     ON NEXT_START.LINE IN (
                         SELECT min(c.LINE)
                         FROM CTX c
                         WHERE
                             (c.PATTERN = 'onStarted' OR c.PATTERN = 'onStartedNullCtx')
                           AND c.THREAD = APP_SAVE_MESG.THREAD
                           AND c.LINE > APP_SAVE_MESG.LINE
                     )
        UNION
        SELECT NEXT_START.LINE FROM
            REQUEST BAD_REQ
                JOIN CTX SAVE_APP
                     ON
                         BAD_REQ.END_LINE IS NULL
                             AND SAVE_APP.ASSESS_CTX = BAD_REQ.ASSESS_CTX
                             AND SAVE_APP.PATTERN = 'savingApp'
                JOIN CONT SAVE_APP_CONT
                     ON SAVE_APP.LINE = SAVE_APP_CONT.LINE
                JOIN MESG APP_SAVE_MESG
                     ON APP_SAVE_MESG.LINE = SAVE_APP_CONT.MESG
                JOIN CTX NEXT_START
                     ON NEXT_START.LINE IN (
                         SELECT min(c.LINE)
                         FROM CTX c
                         WHERE
                             (c.PATTERN = 'onStarted' OR c.PATTERN = 'onStartedNullCtx')
                           AND c.THREAD = APP_SAVE_MESG.THREAD
                           AND c.LINE > APP_SAVE_MESG.LINE
                     )
        UNION
        SELECT SUBMIT_TASK.LINE FROM
            REQUEST BAD_REQ
                JOIN CTX SAVE_APP
                     ON
                         BAD_REQ.END_LINE IS NULL
                             AND SAVE_APP.ASSESS_CTX = BAD_REQ.ASSESS_CTX
                             AND SAVE_APP.PATTERN = 'savingApp'
                JOIN CONT SAVE_APP_CONT
                     ON SAVE_APP.LINE = SAVE_APP_CONT.LINE
                JOIN MESG APP_SAVE_MESG
                     ON APP_SAVE_MESG.LINE = SAVE_APP_CONT.MESG
                JOIN CTX NEXT_START
                     ON NEXT_START.LINE IN (
                         SELECT min(c.LINE)
                         FROM CTX c
                         WHERE
                             (c.PATTERN = 'onStarted' OR c.PATTERN = 'onStartedNullCtx')
                           AND c.THREAD = APP_SAVE_MESG.THREAD
                           AND c.LINE > APP_SAVE_MESG.LINE
                     )
                JOIN CTX SUBMIT_TASK
                     ON
                         SUBMIT_TASK.PATTERN = 'onSubmitted'
                             AND SUBMIT_TASK.TASK_OBJ = NEXT_START.TASK_OBJ
    )
""";
      System.out.println("selectSql = \\n" + selectSql);

      jooq.createView("BAD_REQUEST").as(selectSql).execute();
    }
    System.out.println("BAD_REQUEST view created.");
  }


}