package com.contrastsecurity.agent.loghog.logviews;

import static org.jooq.impl.SQLDataType.*;

import java.sql.*;

import org.jooq.*;
import org.jooq.impl.*;
import org.jooq.meta.jaxb.*;
import org.jooq.meta.jaxb.Generator;

public class ViewCreator {

  final String dbPath;

  public ViewCreator(final String dbPath) {
    this.dbPath = dbPath;
  }

  public static void requestView(Connection connection) {
            DSLContext jooq = DSL.using(connection);
//            jooq.createView("REQUEST").as(
//                    jooq.select(CRUMB.REQ, CRUMB.URL, CRUMB.LINE, CRUMB.TIMESTAMP).from(CRUMB).where();
//
//            );
  }

  public static org.jooq.meta.jaxb.Configuration jooqConfig(final String dbPath) {
    return new org.jooq.meta.jaxb.Configuration()
        .withJdbc(new Jdbc().withDriver("org.h2.Driver").withUrl("jdbc:h2:" + dbPath))
        .withGenerator(
            new Generator()
                .withDatabase(
                    new Database()
                        .withName("org.jooq.meta.h2.H2Database")
                        .withIncludes(".*")
                        .withInputSchema(""))
                //                    .withGenerate()
                .withTarget(new Target().withDirectory("build/generated/sources/jooq/java/main")));
  }
}
