/* (C)2024 */
package com.contrastsecurity.agent.loghog.logshreds;

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
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static com.contrastsecurity.agent.loghog.db.EmbeddedDatabaseFactory.jooq;
import static com.contrastsecurity.agent.loghog.db.LogTable.LOG_TABLE_NAME;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.*;

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
          new ShredRowMetaData("WRAPPED", SQLDataType.VARCHAR, String.class, WRAPPED_RUNNABLE_VAR),
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
    " wrapped a runnable: ",
    "Removing long-living runnable/callable",
    "Cleared expired assessment",
    "AbstractEventExecutor.safeExecute"
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
                      + "AssessmentContext@" + ASSESS_CTX_XTRACT
                      + NO_CONCUR_CTX_XTRACT
                      + NO_APP_CTX_XTRACT
                      + NO_TASK_CLASS_XTRACT
                      + NO_TASK_OBJ_XTRACT
                      + NO_WRAP_INIT_XTRACT
                      + NO_WRAPPED_RUNNABLE_XTRACT
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
                      + "AssessmentContext@" + ASSESS_CTX_XTRACT
                      + NO_CONCUR_CTX_XTRACT
                      + NO_APP_CTX_XTRACT
                      + NO_TASK_CLASS_XTRACT
                      + NO_TASK_OBJ_XTRACT
                      + NO_WRAP_INIT_XTRACT
                      + NO_WRAPPED_RUNNABLE_XTRACT
                      + NO_TRACE_MAP_XTRACT
                      + "$")),
          // Saving app=[com.contrastsecurity.agent.apps.ApplicationContext@19503bf5],
          // HttpContext=[HttpContext{...}], and AssessmentContext=[AssessmentContext@71d8e43d] to
          // ConcurrencyContext=[d@5c7b2372]
          new PatternMetadata(
              "savingApp",
              List.of("Saving app=["),
              Pattern.compile(
                  "^\\s+Saving app=\\["
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
                      + NO_WRAPPED_RUNNABLE_XTRACT
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
                      + NO_WRAPPED_RUNNABLE_XTRACT
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
                      + NO_WRAPPED_RUNNABLE_XTRACT
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
                      + NO_WRAPPED_RUNNABLE_XTRACT
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
                      + WRAPPED_RUNNABLE_XTRACT
                      + " "
                      + NO_CONCUR_CTX_XTRACT
                      + NO_ASSESS_CTX_XTRACT
                      + NO_APP_CTX_XTRACT
                      + NO_TASK_CLASS_XTRACT
                      + NO_TASK_OBJ_XTRACT
                      + NO_TRACE_MAP_XTRACT
                      + "$")),
          new PatternMetadata(
              "clearedAssessment",
              List.of("Cleared expired assessment context"),
              Pattern.compile(
              DEBUG_PREAMBLE_XTRACT
                      + "- Cleared expired assessment context AssessmentContext@"
                              + ASSESS_CTX_XTRACT
                      + "in .+"
                      + NO_CONCUR_CTX_XTRACT
                      + NO_APP_CTX_XTRACT
                      + NO_TASK_CLASS_XTRACT
                      + NO_TASK_OBJ_XTRACT
                      + NO_TRACE_MAP_XTRACT
                      + NO_WRAP_INIT_XTRACT
                      + NO_WRAPPED_RUNNABLE_XTRACT
                      + "$")),

              // 2024-11-14 21:10:53,104 [reactor-http-nio-1 b] DEBUG - AbstractEventExecutor.safeExecute(java.lang.ContrastRunnableWrapper$ContrastClearStateRunnableWrapper@5bb04013) wrapping task io.netty.channel.AbstractChannel$AbstractUnsafe$1@6c6e0f32 with ContrastContext ContrastContext{application=com.contrastsecurity.agent.apps.ApplicationContext@353a9f6a, http=HttpContext{request=null, response=null}, scopeProvider=com.contrastsecurity.agent.scope.ScopeProviderImpl@25ac4989, scopeArchitecture=ScopeArchitecture{scope=0, sampling=0}, additionalScopes=[ASSESS=0, ASSESS_PROPAGATION=0, ASSESS_SAMPLING=0, ASSESS_SOURCE=0, ASSESS_VALIDATOR=0, CONCURRENCY_IGNORE_SUBMIT=0, GENERAL=0, JSP_INCLUDE=0, LOG_ENHANCER=0, OBSERVE_DEADZONE=0, SERVLET=0, SERVLET_MULTIPART=0, SERVLET_PARAMETER_RESOLUTION=0, SERVLET_RESPONSE_HEADER=0, THROWABLE=0, WEBSPHERE_JAR_PREVENTION=0], assessment=null, protect=com.contrastsecurity.agent.plugins.protect.ProtectContext@517692a6, observe=null}
          new PatternMetadata(
              "safeExecute",
              List.of("AbstractEventExecutor.safeExecute"),
              Pattern.compile(
              DEBUG_PREAMBLE_XTRACT
                      + "- AbstractEventExecutor.safeExecute\\("
                              + TASK_OBJ_XTRACT
                      + "\\) wrapping task "
                              + WRAPPED_RUNNABLE_XTRACT
                      + " with ContrastContext .+, http=HttpContext\\{request=.+, response="+ ".+\\}, "
                      + ".+assessment=" + ASSESS_CTX_XTRACT
                      + ".+"
                      + NO_CONCUR_CTX_XTRACT
                      + NO_APP_CTX_XTRACT
                      + NO_TASK_CLASS_XTRACT
                      + NO_TRACE_MAP_XTRACT
                      + "$"
              ))
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

  static final List<String> exampleLogLines = List.of(
    "2024-11-12 16:26:33,392 [reactor-http-nio-2 AssessmentContext] DEBUG - Created context: AssessmentContext@7ecb67d4",
    "2024-11-12 16:27:03,429 [elastic-2 b] DEBUG - elastic-2-40 onStarted java.util.concurrent.ScheduledThreadPoolExecutor$ScheduledFutureTask ScheduledFutureTask@02b2bc79 and got context a@6532cf85 and trace map null",
    "2024-11-12 16:26:53,461 [pool-2-thread-2 b] DEBUG - pool-2-thread-2-15 onStarted java.util.concurrent.Executors$RunnableAdapter RunnableAdapter@7780bf12 but context was null",
    "2024-11-12 16:27:03,428 [Thread-10 b] DEBUG - Thread-10-33 onSubmitted java.lang.Thread Thread@60e40443 into map under context a@53eb78bf and trace map null",
    "2024-11-12 16:27:03,425 [reactor-http-nio-2 AssessmentContext] DEBUG - Preparing to jump context: AssessmentContext@7ecb67d4",
    "\tSaving app=[com.contrastsecurity.agent.apps.ApplicationContext@1a9e4f22], HttpContext=[HttpContext{request=null, response=null}], and AssessmentContext=[AssessmentContext@7ecb67d4] to ConcurrencyContext=[a@00a90db9]",
    "2024-11-12 16:27:03,425 [reactor-http-nio-1 b] DEBUG - io.netty.channel.nio.NioEventLoop@1564c848 wrapped a runnable: io.netty.channel.AbstractChannel$AbstractUnsafe$8@3aac0178 ",
    "2024-11-12 16:27:03,424 [reactor-http-nio-3 AssessmentContext] DEBUG - Cleared expired assessment context AssessmentContext@393a609a in (29999ms)",
    "2024-11-14 21:10:53,104 [reactor-http-nio-1 b] DEBUG - AbstractEventExecutor.safeExecute(java.lang.ContrastRunnableWrapper$ContrastClearStateRunnableWrapper@5bb04013) wrapping task io.netty.channel.AbstractChannel$AbstractUnsafe$1@6c6e0f32 with ContrastContext ContrastContext{application=com.contrastsecurity.agent.apps.ApplicationContext@353a9f6a, http=HttpContext{request=null, response=null}, scopeProvider=com.contrastsecurity.agent.scope.ScopeProviderImpl@25ac4989, scopeArchitecture=ScopeArchitecture{scope=0, sampling=0}, additionalScopes=[ASSESS=0, ASSESS_PROPAGATION=0, ASSESS_SAMPLING=0, ASSESS_SOURCE=0, ASSESS_VALIDATOR=0, CONCURRENCY_IGNORE_SUBMIT=0, GENERAL=0, JSP_INCLUDE=0, LOG_ENHANCER=0, OBSERVE_DEADZONE=0, SERVLET=0, SERVLET_MULTIPART=0, SERVLET_PARAMETER_RESOLUTION=0, SERVLET_RESPONSE_HEADER=0, THROWABLE=0, WEBSPHERE_JAR_PREVENTION=0], assessment=null, protect=com.contrastsecurity.agent.plugins.protect.ProtectContext@517692a6, observe=null}"
  );
  
  public static void main(String[] args) {
    testPatternMatching(exampleLogLines, PATTERN_METADATA, true);
  }
}
