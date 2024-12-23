package com.contrastsecurity.agent.loghog.logshreds;

import com.contrastsecurity.agent.loghog.shred.impl.BaseShred;
import com.contrastsecurity.agent.loghog.shred.impl.BaseShredSource;
import com.contrastsecurity.agent.loghog.shred.CandidateRowSelector;
import com.contrastsecurity.agent.loghog.shred.PatternMetadata;
import com.contrastsecurity.agent.loghog.shred.impl.PatternRowValuesExtractor;
import com.contrastsecurity.agent.loghog.shred.RowClassifier;
import com.contrastsecurity.agent.loghog.shred.RowValuesExtractor;
import com.contrastsecurity.agent.loghog.shred.ShredRowMetaData;
import com.contrastsecurity.agent.loghog.shred.impl.ShredSqlTable;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;

import java.time.LocalDateTime;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static com.contrastsecurity.agent.loghog.db.EmbeddedDatabaseFactory.jooq;
import static com.contrastsecurity.agent.loghog.db.LogTable.LOG_TABLE_NAME;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.*;
import static com.contrastsecurity.agent.loghog.shred.RowClassifier.ANY_PATTERN_ID;

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
          new ShredRowMetaData("MESG", SQLDataType.INTEGER, Integer.class, LAST_MATCH_KEY),
              new ShredRowMetaData(
                      "ENTRY", SQLDataType.VARCHAR, String.class, LOG_TABLE_ENTRY_COL));
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
                     jooq().createIndex("IDX_" + SHRED_TABLE_NAME + "_THREAD_LINE")
                             .on(SHRED_TABLE_NAME, "THREAD", "LINE")
                             .getSQL())
//              List.of()
      );

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


  static final List<PatternMetadata> PATTERN_METADATA =
          List.of(
            new PatternMetadata(ANY_PATTERN_ID,
                List.of(""),
                Pattern.compile(FULL_PREAMBLE_XTRACT + "-( (?<message>.*))?$"))
          );


  static final List<String> EXTRACTED_VAL_NAMES =
          SHRED_METADATA.stream()
                  .map(srmd -> srmd.extractName())
                  .filter(
                          extractName ->
                                  extractName != LOG_TABLE_LINE_COL && extractName != SHRED_TABLE_PATTERN_COL)
                  .toList();

  static final RowValuesExtractor VALUE_EXTRACTOR =
          new PatternRowValuesExtractor(
                  PATTERN_METADATA.stream()
                          .collect(Collectors.toMap(pmd -> pmd.patternId(), pmd -> pmd.pattern())),
                  EXTRACTED_VAL_NAMES);

  // There's no classification required for the mesg shred all rows are parsed identically
  // (or they don't match and become misfits in the continuation table
  public static final BaseShredSource SHRED_SOURCE = new BaseShredSource(LOG_TABLE_NAME, VALUE_EXTRACTOR,
          RowClassifier.allTheSameRowClassifier(),
          CandidateRowSelector.allRowsSelector(LOG_TABLE_NAME)
  );

  public MesgShred() {
    super(SHRED_METADATA, SHRED_SQL_TABLE, MISFITS_METADATA, MISFITS_SQL_TABLE, SHRED_SOURCE);
  }

  static final List<String> exampleLogLines = List.of();

  public static void main(String[] args) {
    testPatternMatching(exampleLogLines, PATTERN_METADATA.stream().filter(pmd -> pmd.patternId().startsWith("channelWriteComplete")).toList(), true);
  }

}
