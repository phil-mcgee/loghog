package com.contrastsecurity.agent.loghog.logviews;

import com.contrastsecurity.agent.loghog.db.EmbeddedDatabaseFactory;
import org.jooq.DSLContext;
import org.jooq.impl.DSL;

import java.sql.Connection;
import java.sql.SQLException;

import static com.contrtastsecurity.agent.loghog.jooq.public_.tables.Crumb.*;

import com.contrtastsecurity.agent.loghog.jooq.public_.tables.Crumb;

public class ViewCreator {

  final String dbPath;

  public ViewCreator(final String dbPath) {
    this.dbPath = dbPath;
  }

  public void createThreadView() throws SQLException {
    System.out.println("Creating THREAD view...");
    try (Connection connect = EmbeddedDatabaseFactory.create(dbPath)) {
      DSLContext jooq = DSL.using(connect);

      final String selectSql = """
SELECT CURRENT.LINE LINE, CURRENT.THREAD THREAD, (
    SELECT min(N.LINE)
    FROM MESG N
    WHERE
      N.THREAD = CURRENT.THREAD
      AND N.LINE > CURRENT.LINE
  ) NEXT_IN_THREAD, (
    SELECT max(P.LINE)
    FROM MESG P
    WHERE
      P.THREAD = CURRENT.THREAD
      AND P.LINE < CURRENT.LINE
  ) PREVIOUS_IN_THREAD
FROM MESG CURRENT
""";
      System.out.println("selectSql = \n" + selectSql);

      //  TOO SLOW    jooq.createMaterializedView("THREAD").as(selectSql).execute();
      // better to find lines as needed in ad hoc query joins
      jooq.createView("THREAD").as(selectSql).execute();
    }
    System.out.println("THREAD view created.");
  }

  public void createRequestView() throws SQLException {
    System.out.println("Creating REQUEST view...");
    try (Connection connect = EmbeddedDatabaseFactory.create(dbPath)) {
      DSLContext jooq = DSL.using(connect);

      final Crumb b = CRUMB.as("begin");
      final Crumb e = CRUMB.as("end");
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
JOIN CTX NEWCTX
ON
  REQBEG.PATTERN = 'req_begin'
  AND NEWCTX.LINE IN (
    SELECT min(LINE)
    FROM CTX
    WHERE
      THREAD = REQBEG.THREAD
      AND PATTERN = 'createdAssessCtx'
      AND LINE > REQBEG.LINE
    )
JOIN TRAK FIRSTTRK
ON FIRSTTRK.LINE IN (
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
LEFT JOIN CRUMB REQEND
ON\s
  REQEND.PATTERN = 'req_end'
  AND REQEND.REQ = REQBEG.REQ
""";
      System.out.println("selectSql = \n" + selectSql);

      jooq.createView("REQUEST").as(selectSql).execute();
    }
    System.out.println("REQUEST view created.");
  }

}