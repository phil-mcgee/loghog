/* (C)2024 */
package com.contrastsecurity.agent.loghog.logshreds;

import com.contrastsecurity.agent.loghog.shred.impl.BaseShredSource;
import com.contrastsecurity.agent.loghog.shred.impl.BaseShred;
import com.contrastsecurity.agent.loghog.shred.PatternMetadata;
import com.contrastsecurity.agent.loghog.shred.impl.PatternRowValuesExtractor;
import com.contrastsecurity.agent.loghog.shred.RowClassifier;
import com.contrastsecurity.agent.loghog.shred.RowValuesExtractor;
import com.contrastsecurity.agent.loghog.shred.ShredRowMetaData;
import com.contrastsecurity.agent.loghog.shred.impl.ShredSqlTable;
import com.contrastsecurity.agent.loghog.shred.pmd.PmdShred;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import static com.contrastsecurity.agent.loghog.db.EmbeddedDatabaseFactory.jooq;
import static com.contrastsecurity.agent.loghog.db.LogTable.LOG_TABLE_NAME;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.DEBUG_PREAMBLE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.THREAD_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TIMESTAMP_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TRACE_MAP_SIZE_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TRACE_MAP_SIZE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TRACE_MAP_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TRACE_MAP_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TRACE_NUM_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TRACE_NUM_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TRACKED_OBJ_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TRACKED_OBJ_XTRACT;
import static com.contrastsecurity.agent.loghog.shred.RowClassifier.ANY_PATTERN_ID;

public class TrakShred extends PmdShred {

  static final String SHRED_TABLE_NAME = "TRAK";
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
          new ShredRowMetaData(
              "TRACE_MAP", SQLDataType.VARCHAR, String.class, TRACE_MAP_VAR),
          new ShredRowMetaData(
              "TRACKED_OBJ", SQLDataType.VARCHAR, String.class, TRACKED_OBJ_VAR),
          new ShredRowMetaData(
              "TRACE_NUM", SQLDataType.INTEGER, Integer.class, TRACE_NUM_VAR),
          new ShredRowMetaData(
              "TRACE_MAP_SIZE", SQLDataType.INTEGER, Integer.class, TRACE_MAP_SIZE_VAR));

  static final String MISFITS_TABLE_NAME = "TRAK_MISFITS";
  static final String MISFITS_KEY_COLUMN = "LINE";

  static final List<ShredRowMetaData> MISFITS_METADATA =
      List.of(
          new ShredRowMetaData(
              "LINE", SQLDataType.INTEGER.notNull(), Integer.class, LOG_TABLE_LINE_COL));

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
          List.of(
              jooq()
                  .createIndex("IDX_" + SHRED_TABLE_NAME + "_" + "OBJ")
                  .on(SHRED_TABLE_NAME, "TRACKED_OBJ")
                  .getSQL(),
              jooq()
                  .createIndex("IDX_" + SHRED_TABLE_NAME + "_" + "TRACE_MAP")
                  .on(SHRED_TABLE_NAME, "TRACE_MAP")
                  .getSQL()));

  static final ShredSqlTable MISFITS_SQL_TABLE =
      new ShredSqlTable(
          MISFITS_TABLE_NAME,
          MISFITS_METADATA,
          MISFITS_KEY_COLUMN,
          List.of(
              // misfits.line references log.line
              jooq()
                  .alterTable(MISFITS_TABLE_NAME)
                  .add(
                      DSL.constraint(MISFITS_TABLE_NAME + "_FK_" + MISFITS_KEY_COLUMN)
                          .foreignKey(MISFITS_KEY_COLUMN)
                          .references(LOG_TABLE_NAME, "LINE"))
                  .getSQL()),
          List.of());

  public static final Set<String> ENTRY_SIGNATURES = Set.of(" items in it) keyed by traced object ");

  // ... DEBUG - Adding trace 35 to map b@2936c20e (with 1 items in it) keyed by traced object
  // String@19c07c00

  static final List<PatternMetadata> PATTERN_METADATA =
          List.of(
                  new PatternMetadata(
                          "track",
                          List.of(""),
                          Pattern.compile(
                                  DEBUG_PREAMBLE_XTRACT
                                          + "- Adding trace "
                                          + TRACE_NUM_XTRACT
                                          + " to map "
                                          + TRACE_MAP_XTRACT
                                          + " \\(with "
                                          + TRACE_MAP_SIZE_XTRACT
                                          + " items in it\\) keyed by traced object +"
                                          + TRACKED_OBJ_XTRACT
                                          + "$")));


  public TrakShred() {
    super(
            SHRED_METADATA, SHRED_SQL_TABLE,
            MISFITS_METADATA, MISFITS_SQL_TABLE,
            ENTRY_SIGNATURES, PATTERN_METADATA,
            true);
  }

  static final List<String> exampleLogLines = List.of(
    "2024-11-12 16:26:32,917 [reactor-http-nio-2 e] DEBUG - Adding trace 1 to map b@2fab5e45 (with 1 items in it) keyed by traced object String@2f3c5c9a"
  );

  public static void main(String[] args) {
    testPatternMatching(exampleLogLines, PATTERN_METADATA, true);
  }
}
