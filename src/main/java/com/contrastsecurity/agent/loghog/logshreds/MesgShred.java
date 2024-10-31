/* (C)2024 */
package com.contrastsecurity.agent.loghog.logshreds;

import static com.contrastsecurity.agent.loghog.db.EmbeddedDatabaseFactory.jooq;
import static com.contrastsecurity.agent.loghog.db.LogDatabaseUtil.LOG_TABLE_NAME;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroup.*;
import static com.contrastsecurity.agent.loghog.shred.RowClassifier.ANY_PATTERN;

import com.contrastsecurity.agent.loghog.shred.AbstractShred;
import com.contrastsecurity.agent.loghog.shred.PatternRowValuesExtractor;
import com.contrastsecurity.agent.loghog.shred.RowValuesExtractor;
import com.contrastsecurity.agent.loghog.shred.ShredSource;
import com.contrastsecurity.agent.loghog.shred.ShredSqlTable;
import java.time.LocalDateTime;
import java.util.*;
import java.util.regex.Pattern;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;

public class MesgShred extends AbstractShred {

  static final String SHRED_TABLE_NAME = "mesg";
  static final String SHRED_KEY_COLUMN = "line";

  static final List<ShredRowMetaData> SHRED_METADATA =
      List.of(
          new ShredRowMetaData(
              "line", SQLDataType.INTEGER.notNull(), Integer.class, LOG_TABLE_LINE_COL),
          new ShredRowMetaData(
              "timestamp",
              SQLDataType.LOCALDATETIME(3).notNull(),
              LocalDateTime.class,
              TIMESTAMP_VAR),
          new ShredRowMetaData("thread", SQLDataType.VARCHAR.notNull(), String.class, THREAD_VAR),
          new ShredRowMetaData("logger", SQLDataType.VARCHAR.notNull(), String.class, LOGGER_VAR),
          new ShredRowMetaData("level", SQLDataType.VARCHAR.notNull(), String.class, LEVEL_VAR),
          new ShredRowMetaData("message", SQLDataType.VARCHAR, String.class, "message"));

  static final String MISFITS_TABLE_NAME = "cont";
  static final String MISFITS_KEY_COLUMN = "line";

  static final List<ShredRowMetaData> MISFITS_METADATA =
      List.of(
          new ShredRowMetaData(
              "line", SQLDataType.INTEGER.notNull(), Integer.class, LOG_TABLE_LINE_COL),
          new ShredRowMetaData("mesg", SQLDataType.INTEGER, Integer.class, LAST_MATCH_KEY));

  static final ShredSqlTable SHRED_SQL_TABLE =
      new ShredSqlTable(
          SHRED_TABLE_NAME,
          SHRED_METADATA,
          SHRED_KEY_COLUMN,
          List.of(
              // mesg.line references log.line
              jooq()
                  .alterTable(SHRED_TABLE_NAME)
                  .add(
                      DSL.constraint(SHRED_TABLE_NAME + "_FK_" + SHRED_KEY_COLUMN)
                          .foreignKey(SHRED_KEY_COLUMN)
                          .references(LOG_TABLE_NAME, "line"))
                  .getSQL()),
          /* is there really any point to index on thread?
             Arrays.asList(
                     jooq().createIndex("idx_" + SHRED_TABLE_NAME + "_thread")
                             .on(SHRED_TABLE_NAME, "thread")
                             .getSQL())
          */
          List.of());

  static final ShredSqlTable MISFITS_SQL_TABLE =
      new ShredSqlTable(
          MISFITS_TABLE_NAME,
          MISFITS_METADATA,
          MISFITS_KEY_COLUMN,
          List.of(
              // cont.line references log.line
              jooq()
                  .alterTable(MISFITS_TABLE_NAME)
                  .add(
                      DSL.constraint(MISFITS_TABLE_NAME + "_FK_" + MISFITS_KEY_COLUMN)
                          .foreignKey(MISFITS_KEY_COLUMN)
                          .references(LOG_TABLE_NAME, "line"))
                  .getSQL(),
              // cont.mesg references mesg.line
              jooq()
                  .alterTable(MISFITS_TABLE_NAME)
                  .add(
                      DSL.constraint(MISFITS_TABLE_NAME + "_FK_" + "mesg")
                          .foreignKey("mesg")
                          .references(SHRED_TABLE_NAME, "line"))
                  .getSQL()),
          List.of());

  public static final RowValuesExtractor VALUE_EXTRACTOR =
      new PatternRowValuesExtractor(
          Map.of(ANY_PATTERN, Pattern.compile(FULL_PREAMBLE_XTRACT + "-( (?<message>.*))?$")),
          Arrays.asList(TIMESTAMP_VAR, THREAD_VAR, LOGGER_VAR, LEVEL_VAR, "message"));

  // There's no classification required for the mesg shred all rows are parsed identically
  // (or they don't match and become misfits in the continuation table
  public static final ShredSource SHRED_SOURCE = new ShredSource(LOG_TABLE_NAME, VALUE_EXTRACTOR);

  public MesgShred() {
    super(SHRED_METADATA, SHRED_SQL_TABLE, MISFITS_METADATA, MISFITS_SQL_TABLE, SHRED_SOURCE);
  }
}
