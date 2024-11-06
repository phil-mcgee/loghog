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

  public void createRequestView() throws SQLException {
    System.out.println("Creating REQUEST view...");
    try (Connection connect = EmbeddedDatabaseFactory.create(dbPath)) {
      DSLContext jooq = DSL.using(connect);

      final Crumb b = CRUMB.as("begin");
      final Crumb e = CRUMB.as("end");
      final String selectSql = """
SELECT 
  b.REQ, 
  b.URL, 
  b.LINE BEGIN_LINE, 
  b.TIMESTAMP BEGIN_TIME, 
  e.LINE END_LINE, 
  e.TIMESTAMP END_TIME
FROM (SELECT * FROM CRUMB WHERE PATTERN = 'req_begin') b
LEFT JOIN (SELECT * FROM CRUMB WHERE PATTERN = 'req_end') e
ON b.REQ = e.REQ
""";
      System.out.println("selectSql = \n" + selectSql);

      jooq.createView("REQUEST").as(selectSql).execute();
    }
    System.out.println("REQUEST view created.");
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

//      jooq.createMaterializedView("THREAD").as(selectSql).execute();
      jooq.createView("THREAD").as(selectSql).execute();
    }
    System.out.println("THREAD view created.");
  }

}