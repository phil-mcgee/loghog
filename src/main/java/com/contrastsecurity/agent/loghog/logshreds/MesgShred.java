/* (C)2024 */
package com.contrastsecurity.agent.loghog.logshreds;

import static com.contrastsecurity.agent.loghog.db.EmbeddedDatabaseFactory.jooq;
import static com.contrastsecurity.agent.loghog.db.LogDatabaseUtil.LOG_TABLE_NAME;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.*;
import static com.contrastsecurity.agent.loghog.shred.RowClassifier.ANY_PATTERN_ID;

import com.contrastsecurity.agent.loghog.shred.BaseShred;
import com.contrastsecurity.agent.loghog.shred.PatternRowValuesExtractor;
import com.contrastsecurity.agent.loghog.shred.RowValuesExtractor;
import com.contrastsecurity.agent.loghog.shred.ShredRowMetaData;
import com.contrastsecurity.agent.loghog.shred.ShredSource;
import com.contrastsecurity.agent.loghog.shred.ShredSqlTable;
import java.time.LocalDateTime;
import java.util.*;
import java.util.regex.Pattern;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;

public class MesgShred extends BaseShred {

  static final String SHRED_TABLE_NAME = "MESG";
  static final String SHRED_KEY_COLUMN = "LINE";

  static final List<ShredRowMetaData> SHRED_METADATA =
      List.of(
          new ShredRowMetaData(
              "LINE", SQLDataType.INTEGER.notNull(), Integer.class, LOG_TABLE_LINE_COL),
          new ShredRowMetaData(
              "TIMESTAMP",
              SQLDataType.LOCALDATETIME(3).notNull(),
              LocalDateTime.class,
              TIMESTAMP_VAR),
          new ShredRowMetaData("THREAD", SQLDataType.VARCHAR.notNull(), String.class, THREAD_VAR),
          new ShredRowMetaData("LOGGER", SQLDataType.VARCHAR.notNull(), String.class, LOGGER_VAR),
          new ShredRowMetaData("LEVEL", SQLDataType.VARCHAR.notNull(), String.class, LEVEL_VAR),
          new ShredRowMetaData("MESSAGE", SQLDataType.VARCHAR, String.class, "message"));

  static final String MISFITS_TABLE_NAME = "CONT";
  static final String MISFITS_KEY_COLUMN = "LINE";

  static final List<ShredRowMetaData> MISFITS_METADATA =
      List.of(
          new ShredRowMetaData(
              "LINE", SQLDataType.INTEGER.notNull(), Integer.class, LOG_TABLE_LINE_COL),
          new ShredRowMetaData("MESG", SQLDataType.INTEGER, Integer.class, LAST_MATCH_KEY));

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
                          .references(LOG_TABLE_NAME, "LINE"))
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
                          .references(LOG_TABLE_NAME, "LINE"))
                  .getSQL(),
              // cont.mesg references mesg.line
              jooq()
                  .alterTable(MISFITS_TABLE_NAME)
                  .add(
                      DSL.constraint(MISFITS_TABLE_NAME + "_FK_" + "MESG")
                          .foreignKey("MESG")
                          .references(SHRED_TABLE_NAME, "LINE"))
                  .getSQL()),
          List.of());

  public static final RowValuesExtractor VALUE_EXTRACTOR =
      new PatternRowValuesExtractor(
          Map.of(ANY_PATTERN_ID, Pattern.compile(FULL_PREAMBLE_XTRACT + "-( (?<message>.*))?$")),
          SHRED_METADATA.stream()
              .map(srmd -> srmd.extractName())
              .filter(extractName -> extractName != LOG_TABLE_LINE_COL)
              .toList());

  // There's no classification required for the mesg shred all rows are parsed identically
  // (or they don't match and become misfits in the continuation table
  public static final ShredSource SHRED_SOURCE = new ShredSource(LOG_TABLE_NAME, VALUE_EXTRACTOR);

  public MesgShred() {
    super(SHRED_METADATA, SHRED_SQL_TABLE, MISFITS_METADATA, MISFITS_SQL_TABLE, SHRED_SOURCE);
  }
}
