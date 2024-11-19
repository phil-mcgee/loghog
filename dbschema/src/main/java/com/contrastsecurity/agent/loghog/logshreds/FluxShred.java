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
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static com.contrastsecurity.agent.loghog.db.EmbeddedDatabaseFactory.jooq;
import static com.contrastsecurity.agent.loghog.db.LogTable.LOG_TABLE_NAME;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.APP_CTX_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.APP_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.ASSESS_CTX_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.ASSESS_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.CONCUR_CTX_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.CONCUR_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.DEBUG_PREAMBLE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.JUMPED_ASSESS_CTX_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.JUMPED_ASSESS_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_APP_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_ASSESS_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_CONCUR_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_JUMPED_ASSESS_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_REQ_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_RESP_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_TASK_CLASS_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_TASK_OBJ_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_THREAD_LOGGER_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_TIMESTAMP_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_TRACE_MAP_SIZE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_TRACE_MAP_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_URL_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_WRAPPED_RUNNABLE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_WRAP_INIT_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.REQ_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.REQ_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.RESP_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.RESP_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TASK_CLASS_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TASK_CLASS_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TASK_OBJ_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TASK_OBJ_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.THREAD_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TIMESTAMP_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TRACE_MAP_SIZE_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TRACE_MAP_SIZE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TRACE_MAP_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TRACE_MAP_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.URL_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.URL_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.WRAPPED_RUNNABLE_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.WRAPPED_RUNNABLE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.WRAP_INIT_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.WRAP_INIT_XTRACT;

public class FluxShred extends BaseShred {

  static final String SHRED_TABLE_NAME = "FLUX";
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
          new ShredRowMetaData("REQ", SQLDataType.VARCHAR, String.class, REQ_VAR),
          new ShredRowMetaData("RESP", SQLDataType.VARCHAR, String.class, RESP_VAR),
          new ShredRowMetaData("URL", SQLDataType.VARCHAR, String.class, URL_VAR),
          new ShredRowMetaData("APP_CTX", SQLDataType.VARCHAR, String.class, APP_CTX_VAR),
          new ShredRowMetaData("TASK_CLASS", SQLDataType.VARCHAR, String.class, TASK_CLASS_VAR),
          new ShredRowMetaData("TASK_OBJ", SQLDataType.VARCHAR, String.class, TASK_OBJ_VAR),
          new ShredRowMetaData("WRAP_INIT", SQLDataType.VARCHAR, String.class, WRAP_INIT_VAR),
          new ShredRowMetaData("WRAPPED", SQLDataType.VARCHAR, String.class, WRAPPED_RUNNABLE_VAR),
          new ShredRowMetaData("TRACE_MAP", SQLDataType.VARCHAR, String.class, TRACE_MAP_VAR),
              new ShredRowMetaData(
                      "TRACE_MAP_SIZE", SQLDataType.INTEGER.notNull(), Integer.class, TRACE_MAP_SIZE_VAR),
              new ShredRowMetaData(
                      "JUMPED_ASSESS_CTX", SQLDataType.BOOLEAN, Boolean.class, JUMPED_ASSESS_CTX_VAR));

  static final String MISFITS_TABLE_NAME = "FLUX_MISFITS";
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
    "- AbstractEventExecutor.safeExecute(",
    "- ContrastNettyHttpDispatcherImpl."
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

  static final String ASSESS_NONNULL_XTRACTS = ASSESS_CTX_XTRACT + "\\{traceMap="
          + TRACE_MAP_XTRACT + " \\(with " + TRACE_MAP_SIZE_XTRACT + " items in it\\), jumpedContexts=" + JUMPED_ASSESS_CTX_XTRACT + "\\}\\}";
  static final String ASSESS_NULL_XTRACTS = ASSESS_CTX_XTRACT + "\\}" + NO_TRACE_MAP_XTRACT + NO_TRACE_MAP_SIZE_XTRACT + NO_JUMPED_ASSESS_CTX_XTRACT ;
  static final String WITH_WRAPPED_RUNNABLE_XTRACT =  "\\) wrapping task " + WRAPPED_RUNNABLE_XTRACT+ " with ContrastContext";
  static final String WITHOUT_WRAPPED_RUNNABLE_XTRACT =  "\\) with ContrastContext";
  static final String START_CONTRAST_CONTEXT_EXTRACT = " ContrastContext\\{http=HttpContext\\{" + REQ_XTRACT + ", " + RESP_XTRACT + "\\}, uri='" + URL_XTRACT + "',assessment=";
  static final List<PatternMetadata> PATTERN_METADATA =
      List.of(
              new PatternMetadata(
                      "safeExecuteWrappingAssessNonnull",
                      List.of("- AbstractEventExecutor.safeExecute(", " wrapping task ", "{traceMap="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- AbstractEventExecutor.safeExecute\\("
                                      + TASK_OBJ_XTRACT
                                      + WITH_WRAPPED_RUNNABLE_XTRACT
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NONNULL_XTRACTS
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "safeExecuteWrappingAssessNull",
                      List.of("- AbstractEventExecutor.safeExecute(", " wrapping task "),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- AbstractEventExecutor.safeExecute\\("
                                      + TASK_OBJ_XTRACT
                                      + WITH_WRAPPED_RUNNABLE_XTRACT
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NULL_XTRACTS
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + "$")),
              new PatternMetadata(
              "safeExecuteAssessNonnull",
              List.of("- AbstractEventExecutor.safeExecute(", "{traceMap="),
              Pattern.compile(
                  DEBUG_PREAMBLE_XTRACT
                      + "- AbstractEventExecutor.safeExecute\\("
                      + TASK_OBJ_XTRACT
                      + WITHOUT_WRAPPED_RUNNABLE_XTRACT
                          + START_CONTRAST_CONTEXT_EXTRACT
                          + ASSESS_NONNULL_XTRACTS
                          + NO_CONCUR_CTX_XTRACT
                      + NO_APP_CTX_XTRACT
                      + NO_TASK_CLASS_XTRACT
                      + NO_WRAP_INIT_XTRACT
                      + NO_WRAPPED_RUNNABLE_XTRACT
                      + "$")),
              new PatternMetadata(
                      "safeExecuteAssessNull",
              List.of("- AbstractEventExecutor.safeExecute("),
              Pattern.compile(
                      DEBUG_PREAMBLE_XTRACT
                              + "- AbstractEventExecutor.safeExecute\\("
                              + TASK_OBJ_XTRACT
                              + WITHOUT_WRAPPED_RUNNABLE_XTRACT
                              + START_CONTRAST_CONTEXT_EXTRACT
                              + ASSESS_NULL_XTRACTS
                              + NO_CONCUR_CTX_XTRACT
                              + NO_APP_CTX_XTRACT
                              + NO_TASK_CLASS_XTRACT
                              + NO_WRAP_INIT_XTRACT
                              + NO_WRAPPED_RUNNABLE_XTRACT
                              + "$")) //,
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

  public FluxShred() {
    super(SHRED_METADATA, SHRED_SQL_TABLE, MISFITS_METADATA, MISFITS_SQL_TABLE, SHRED_SOURCE);
  }

  static final List<String> exampleLogLines = List.of(
    "2024-11-19 15:25:05,605 [reactor-http-nio-1 ConcurrencyContextMap] DEBUG - AbstractEventExecutor.safeExecute(java.lang.ContrastRunnableWrapper$ContrastClearStateRunnableWrapper@0d85f6cb) wrapping task io.netty.bootstrap.ServerBootstrap$1$1@61352a5b with ContrastContext ContrastContext{http=HttpContext{null, null}, uri='null',assessment=null}",
            "2024-11-19 15:25:09,255 [reactor-http-nio-2 ConcurrencyContextMap] DEBUG - AbstractEventExecutor.safeExecute(io.netty.channel.AbstractChannel$AbstractUnsafe$1@05a194cb) with ContrastContext ContrastContext{http=HttpContext{null, null}, uri='null',assessment=null}",
//            "2024-11-19 15:25:09,391 [reactor-http-nio-2 ContrastNettyHttpDispatcherImpl] DEBUG - ContrastNettyHttpDispatcherImpl.onFireChannelRead(ContrastContext{http=HttpContext{null, null}, uri='null',assessment=null}, io.netty.channel.DefaultChannelPipeline$HeadContext@693617e2) with channel NioSocketChannel@350aa7be",
//            "2024-11-19 15:25:09,423 [reactor-http-nio-2 ContrastNettyHttpDispatcherImpl] DEBUG - ContrastNettyHttpDispatcherImpl.onRequestDecoded(DefaultHttpRequest@06dbdb45, ContrastContext{http=HttpContext{null, null}, uri='null',assessment=null}) with channel NioSocketChannel@350aa7be and decoderState SKIP_CONTROL_CHARS",
//            "2024-11-19 15:25:09,840 [reactor-http-nio-1 ContrastNettyHttpDispatcherImpl] DEBUG - ContrastNettyHttpDispatcherImpl.onFireChannelRead(ContrastContext{http=HttpContext{HttpRequest@058eebdb, null}, uri='/sources/v5_0/requestPart',assessment=AssessmentContext@3f7ffb2b{traceMap=TraceMap@74c3195e (with 0 items in it), jumpedContexts=false}}, io.netty.channel.CombinedChannelDuplexHandler$1@757516fe) with channel NioSocketChannel@6fe4e100",
//            "2024-11-19 15:25:10,019 [reactor-http-nio-2 ContrastNettyHttpDispatcherImpl] DEBUG - ContrastNettyHttpDispatcherImpl.onFireChannelRead(ContrastContext{http=HttpContext{HttpRequest@7c49fe7b, null}, uri='/sources/v5_0/httpEntity',assessment=AssessmentContext@380f27c6{traceMap=TraceMap@4d3c547f (with 7 items in it), jumpedContexts=false}}, io.netty.channel.DefaultChannelHandlerContext@2a28dc33) with channel NioSocketChannel@5965392f",
//            "2024-11-19 15:25:10,196 [reactor-http-nio-3 ContrastNettyHttpDispatcherImpl] DEBUG - ContrastNettyHttpDispatcherImpl.onRequestDecoded(DefaultHttpRequest@02234d3f, ContrastContext{http=HttpContext{null, null}, uri='null',assessment=AssessmentContext@1c6cbee5{traceMap=TraceMap@70d97527 (with 41 items in it), jumpedContexts=true}}) with channel NioSocketChannel@7a76c8cb and decoderState READ_FIXED_LENGTH_CONTENT",
//            "2024-11-19 15:25:10,197 [reactor-http-nio-1 ContrastNettyHttpDispatcherImpl] DEBUG - ContrastNettyHttpDispatcherImpl.onRequestDecoded(DefaultHttpRequest@073c013c, ContrastContext{http=HttpContext{null, null}, uri='null',assessment=AssessmentContext@3f7ffb2b{traceMap=TraceMap@74c3195e (with 55 items in it), jumpedContexts=true}}) with channel NioSocketChannel@2600da01 and decoderState READ_FIXED_LENGTH_CONTENT",
            "2024-11-19 15:25:10,421 [reactor-http-nio-4 ConcurrencyContextMap] DEBUG - AbstractEventExecutor.safeExecute(io.netty.channel.AbstractChannel$AbstractUnsafe$1@016bfa6d) with ContrastContext ContrastContext{http=HttpContext{null, null}, uri='null',assessment=AssessmentContext@12790b10{traceMap=TraceMap@18eb4ed2 (with 41 items in it), jumpedContexts=true}}",
//            "2024-11-19 15:25:10,589 [reactor-http-nio-4 ContrastNettyHttpDispatcherImpl] DEBUG - ContrastNettyHttpDispatcherImpl.onFireChannelRead(ContrastContext{http=HttpContext{null, null}, uri='null',assessment=AssessmentContext@102b6a31{traceMap=TraceMap@4ea79195 (with 57 items in it), jumpedContexts=true}}, io.netty.channel.DefaultChannelPipeline$HeadContext@3f623d40) with channel NioSocketChannel@267f0e0b",
            "2024-11-19 15:25:10,685 [reactor-http-nio-4 ConcurrencyContextMap] DEBUG - AbstractEventExecutor.safeExecute(java.lang.ContrastRunnableWrapper$ContrastClearStateRunnableWrapper@01cd0fa8) wrapping task reactor.netty.http.server.HttpServerOperations$$Lambda$896/0x000000084088d440@2a6d8822 with ContrastContext ContrastContext{http=HttpContext{null, null}, uri='null',assessment=AssessmentContext@71193ced{traceMap=TraceMap@17e66f95 (with 39 items in it), jumpedContexts=true}}"
  );
  
  public static void main(String[] args) {
    testPatternMatching(exampleLogLines, PATTERN_METADATA, true);
  }
}
