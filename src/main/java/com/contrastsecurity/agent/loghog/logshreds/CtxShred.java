/* (C)2024 */
package com.contrastsecurity.agent.loghog.logshreds;

import static com.contrastsecurity.agent.loghog.db.EmbeddedDatabaseFactory.jooq;
import static com.contrastsecurity.agent.loghog.db.LogDatabaseUtil.LOG_TABLE_NAME;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.*;

import com.contrastsecurity.agent.loghog.shred.BaseShred;
import com.contrastsecurity.agent.loghog.shred.PatternMetadata;
import com.contrastsecurity.agent.loghog.shred.PatternRowValuesExtractor;
import com.contrastsecurity.agent.loghog.shred.PatternSignatures;
import com.contrastsecurity.agent.loghog.shred.RowClassifier;
import com.contrastsecurity.agent.loghog.shred.RowValuesExtractor;
import com.contrastsecurity.agent.loghog.shred.ShredRowMetaData;
import com.contrastsecurity.agent.loghog.shred.ShredSource;
import com.contrastsecurity.agent.loghog.shred.ShredSqlTable;
import com.contrastsecurity.agent.loghog.shred.TextSignatureRowClassifier;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;

public class CtxShred extends BaseShred {

  static final String SHRED_TABLE_NAME = "CTX";
  static final String SHRED_KEY_COLUMN = "LINE";

  static final List<ShredRowMetaData> SHRED_METADATA =
      List.of(
          new ShredRowMetaData(
              "LINE", SQLDataType.INTEGER.notNull(), Integer.class, LOG_TABLE_LINE_COL),
          new ShredRowMetaData(
              "TIMESTAMP", SQLDataType.LOCALDATETIME(3), LocalDateTime.class, TIMESTAMP_VAR),
          new ShredRowMetaData("THREAD", SQLDataType.VARCHAR, String.class, THREAD_VAR),
          new ShredRowMetaData(
              "PATTERN", SQLDataType.VARCHAR.notNull(), String.class, SHRED_TABLE_PATTERN_COL),
          new ShredRowMetaData("CONCUR_CTX", SQLDataType.VARCHAR, String.class, CONCUR_CTX_VAR),
          new ShredRowMetaData("ASSESS_CTX", SQLDataType.VARCHAR, String.class, ASSESS_CTX_VAR),
          new ShredRowMetaData("APP_CTX", SQLDataType.VARCHAR, String.class, APP_CTX_VAR),
          new ShredRowMetaData("TASK_CLASS", SQLDataType.VARCHAR, String.class, TASK_CLASS_VAR),
          new ShredRowMetaData("TASK_OBJ", SQLDataType.VARCHAR, String.class, TASK_OBJ_VAR),
          new ShredRowMetaData("WRAP_INIT", SQLDataType.VARCHAR, String.class, WRAP_INIT_VAR),
          new ShredRowMetaData("RUNNABLE", SQLDataType.VARCHAR, String.class, RUNNABLE_VAR),
          new ShredRowMetaData("TRACE_MAP", SQLDataType.VARCHAR, String.class, TRACE_MAP_VAR));

  static final String MISFITS_TABLE_NAME = "CTX_MISFITS";
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
              //              jooq()
              //                  .createIndex("IDX_" + SHRED_TABLE_NAME + "_" + "REQ")
              //                  .on(SHRED_TABLE_NAME, "REQ")
              //                  .getSQL(),
              //              jooq()
              //                  .createIndex("IDX_" + SHRED_TABLE_NAME + "_" + "REQ" + "_" +
              // "PATTERN")
              //                  .on(SHRED_TABLE_NAME, "REQ", "PATTERN")
              //                  .getSQL()
              ));

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
                  .getSQL()),
          List.of());

  public static final String[] ENTRY_SIGNATURES = {
    "- Created context: ",
    "- Preparing to jump context: ",
    "Saving app=[",
    " into map under context ",
    " onStarted ",
    " wrapped a runnable: "
  };

  static String entryTestSql() {
    final StringBuilder sb = new StringBuilder();
    String conjunction = "";
    for (String signature : ENTRY_SIGNATURES) {
      sb.append(conjunction).append("LOG.ENTRY like '%");
      sb.append(signature).append("%'");
      if (conjunction.isEmpty()) {
        conjunction = " OR ";
      }
    }
    return sb.toString();
  }

  //  static String entryTestSql() {
  //    return "LOG.LINE = 27621";
  //  }

  static final List<PatternMetadata> PATTERN_METADATA =
      List.of(
          // 2024-10-28 14:36:25,737 [reactor-http-nio-3 AssessmentContext] DEBUG - Created context:
          // AssessmentContext@2bf76c58
          new PatternMetadata(
              "createdAssessCtx",
              List.of("- Created context:"),
              Pattern.compile(
                  DEBUG_PREAMBLE_XTRACT
                      + "- Created context: "
                      + ASSESS_CTX_XTRACT
                      + NO_CONCUR_CTX_XTRACT
                      + NO_APP_CTX_XTRACT
                      + NO_TASK_CLASS_XTRACT
                      + NO_TASK_OBJ_XTRACT
                      + NO_WRAP_INIT_XTRACT
                      + NO_RUNNABLE_XTRACT
                      + NO_TRACE_MAP_XTRACT
                      + "$")),
          // 2024-10-28 14:36:25,872 [reactor-http-nio-2 AssessmentContext] DEBUG - Preparing to
          // jump context: AssessmentContext@71d8e43d
          new PatternMetadata(
              "prepareJump",
              List.of("- Preparing to jump context: "),
              Pattern.compile(
                  DEBUG_PREAMBLE_XTRACT
                      + "- Preparing to jump context: "
                      + ASSESS_CTX_XTRACT
                      + NO_CONCUR_CTX_XTRACT
                      + NO_APP_CTX_XTRACT
                      + NO_TASK_CLASS_XTRACT
                      + NO_TASK_OBJ_XTRACT
                      + NO_WRAP_INIT_XTRACT
                      + NO_RUNNABLE_XTRACT
                      + NO_TRACE_MAP_XTRACT
                      + "$")),
          // Saving app=[com.contrastsecurity.agent.apps.ApplicationContext@19503bf5],
          // HttpContext=[HttpContext{...}], and AssessmentContext=[AssessmentContext@71d8e43d] to
          // ConcurrencyContext=[d@5c7b2372]
          new PatternMetadata(
              "savingApp",
              List.of("Saving app=["),
              Pattern.compile(
                  "\\s+Saving app=\\["
                      + APP_CTX_XTRACT
                      + "], HttpContext=\\[.+}], and AssessmentContext=\\["
                      + "(AssessmentContext@)?"
                      + ASSESS_CTX_XTRACT
                      + "] to ConcurrencyContext=\\["
                      + CONCUR_CTX_XTRACT
                      + "]"
                      + NO_TIMESTAMP_XTRACT
                      + NO_THREAD_LOGGER_XTRACT
                      + NO_TASK_CLASS_XTRACT
                      + NO_TASK_OBJ_XTRACT
                      + NO_WRAP_INIT_XTRACT
                      + NO_RUNNABLE_XTRACT
                      + NO_TRACE_MAP_XTRACT
                      + "$")),
          // 2024-10-28 14:36:23,207 [main b] DEBUG - main-1 onSubmitted
          // java.util.zip.ZipFile$CleanableResource$FinalizableResource
          // FinalizableResource@4dec9271 into map under context d@7609c5c0 and trace map null
          new PatternMetadata(
              "onSubmitted",
              List.of(" onSubmitted ", " into map under context "),
              Pattern.compile(
                  DEBUG_PREAMBLE_XTRACT
                      + "- [\\S ]+ onSubmitted "
                      + TASK_CLASS_XTRACT
                      + " "
                      + TASK_OBJ_XTRACT
                      + " into map under context "
                      + CONCUR_CTX_XTRACT
                      + " and trace map "
                      + TRACE_MAP_XTRACT
                      + NO_ASSESS_CTX_XTRACT
                      + NO_APP_CTX_XTRACT
                      + NO_WRAP_INIT_XTRACT
                      + NO_RUNNABLE_XTRACT
                      + "$")),
          // 2024-10-28 14:36:22,782 [background-preinit b] DEBUG - background-preinit-29 onStarted
          // java.lang.Thread Thread@7dfca9e6 and got context d@113a6636 and trace map null
          new PatternMetadata(
              "onStarted",
              List.of(" onStarted ", " and got context "),
              Pattern.compile(
                  DEBUG_PREAMBLE_XTRACT
                      + "- [\\S ]+ onStarted "
                      + TASK_CLASS_XTRACT
                      + " "
                      + TASK_OBJ_XTRACT
                      + " and got context "
                      + CONCUR_CTX_XTRACT
                      + " and trace map "
                      + TRACE_MAP_XTRACT
                      + NO_ASSESS_CTX_XTRACT
                      + NO_APP_CTX_XTRACT
                      + NO_WRAP_INIT_XTRACT
                      + NO_RUNNABLE_XTRACT
                      + "$")),
          // 2024-10-28 14:36:22,782 [background-preinit b] DEBUG - background-preinit-29 onStarted
          // java.lang.Thread Thread@7dfca9e6 and got context d@113a6636 and trace map null
          new PatternMetadata(
              "onStartedNullCtx",
              List.of(" onStarted ", " but context was null"),
              Pattern.compile(
                  DEBUG_PREAMBLE_XTRACT
                      + "- [\\S ]+ onStarted "
                      + TASK_CLASS_XTRACT
                      + " "
                      + TASK_OBJ_XTRACT
                      + " but context was null"
                      + NO_CONCUR_CTX_XTRACT
                      + NO_TRACE_MAP_XTRACT
                      + NO_ASSESS_CTX_XTRACT
                      + NO_APP_CTX_XTRACT
                      + NO_WRAP_INIT_XTRACT
                      + NO_RUNNABLE_XTRACT
                      + "$")),
          // 2024-10-28 14:36:24,863 [main b] DEBUG - io.netty.channel.nio.NioEventLoop@f8cd5d7
          // wrapped a runnable: io.netty.channel.AbstractChannel$AbstractUnsafe$1@4d1d30dc
          new PatternMetadata(
              "wrapped",
              List.of("wrapped a runnable:"),
              Pattern.compile(
                  DEBUG_PREAMBLE_XTRACT
                      + "- "
                      + WRAP_INIT_XTRACT
                      + " wrapped a runnable: "
                      + RUNNABLE_XTRACT
                      + " "
                      + NO_CONCUR_CTX_XTRACT
                      + NO_ASSESS_CTX_XTRACT
                      + NO_APP_CTX_XTRACT
                      + NO_TASK_CLASS_XTRACT
                      + NO_TASK_OBJ_XTRACT
                      + NO_TRACE_MAP_XTRACT
                      + "$")));

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

  static final RowClassifier ROW_CLASSIFIER =
      new TextSignatureRowClassifier(
          PATTERN_METADATA.stream()
              .map(pmd -> new PatternSignatures(pmd.patternId(), pmd.signatures()))
              .toList());

  public static final ShredSource SHRED_SOURCE =
      new ShredSource(
          LOG_TABLE_NAME,
          VALUE_EXTRACTOR,
          ROW_CLASSIFIER,
          jooq().select(DSL.asterisk()).from(LOG_TABLE_NAME).where(entryTestSql()).getSQL());

  public CtxShred() {
    super(SHRED_METADATA, SHRED_SQL_TABLE, MISFITS_METADATA, MISFITS_SQL_TABLE, SHRED_SOURCE);
  }

  public static void main(String[] args) {
    final String matchThis =
        "2024-10-28 14:36:55,960 [Signal Dispatcher b] DEBUG - Signal Dispatcher-4 onSubmitted jdk.internal.misc.Signal$1 jdk.internal.misc.Signal$1@2f36c092 into map under context d@57db5523 and trace map null";

    final Pattern toTest =
        PATTERN_METADATA.stream()
            .filter(pmd -> "onSubmitted".equals(pmd.patternId()))
            .map(PatternMetadata::pattern)
            .findFirst()
            .orElseGet(null);
    System.out.println("Pattern: " + toTest);
    System.out.println("Matches? " + matchThis);
    Matcher matcher = toTest.matcher(matchThis);
    System.out.println(" = " + matcher.matches());
    if (matcher.matches()) {
      for (Map.Entry<String, Integer> entry : matcher.namedGroups().entrySet()) {
        final String name = entry.getKey();
        final Integer groupIdx = entry.getValue();
        System.out.println(
            "group("
                + name
                + ") -> \'"
                + String.valueOf(matcher.group(groupIdx))
                + "\'"
                + " == null ? "
                + String.valueOf(matcher.group(name) == null));
      }
    }
  }
}
