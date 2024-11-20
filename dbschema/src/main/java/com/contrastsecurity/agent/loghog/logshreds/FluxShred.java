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

import java.net.http.HttpRequest;
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
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.CHANNEL_HANDLER_CTX_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.CHANNEL_HANDLER_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.CHANNEL_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.CHANNEL_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.CONCUR_CTX_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.CONCUR_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.DEBUG_PREAMBLE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.DECODER_STATE_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.DECODER_STATE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.JUMPED_ASSESS_CTX_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.JUMPED_ASSESS_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NETTY_HTTP_MSG_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NETTY_HTTP_MSG_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_APP_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_ASSESS_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_CHANNEL_HANDLER_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_CHANNEL_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_CONCUR_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_DECODER_STATE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_JUMPED_ASSESS_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_NETTY_HTTP_MSG_XTRACT;
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
          new ShredRowMetaData("LINE", SQLDataType.INTEGER.notNull(), Integer.class, LOG_TABLE_LINE_COL),
          new ShredRowMetaData("TIMESTAMP", SQLDataType.LOCALDATETIME(3), LocalDateTime.class, TIMESTAMP_VAR),
          new ShredRowMetaData("THREAD", SQLDataType.VARCHAR, String.class, THREAD_VAR),
          new ShredRowMetaData("PATTERN", SQLDataType.VARCHAR.notNull(), String.class, SHRED_TABLE_PATTERN_COL),
          new ShredRowMetaData("CHANNEL", SQLDataType.VARCHAR, String.class, CHANNEL_VAR),
          new ShredRowMetaData("ASSESS_CTX", SQLDataType.VARCHAR, String.class, ASSESS_CTX_VAR),
          new ShredRowMetaData("REQ", SQLDataType.VARCHAR, String.class, REQ_VAR),
          new ShredRowMetaData("URL", SQLDataType.VARCHAR, String.class, URL_VAR),
          new ShredRowMetaData("TASK_CLASS", SQLDataType.VARCHAR, String.class, TASK_CLASS_VAR),
          new ShredRowMetaData("TASK_OBJ", SQLDataType.VARCHAR, String.class, TASK_OBJ_VAR),
          new ShredRowMetaData("WRAP_INIT", SQLDataType.VARCHAR, String.class, WRAP_INIT_VAR),
          new ShredRowMetaData("WRAPPED", SQLDataType.VARCHAR, String.class, WRAPPED_RUNNABLE_VAR),
          new ShredRowMetaData("TRACE_MAP", SQLDataType.VARCHAR, String.class, TRACE_MAP_VAR),
          new ShredRowMetaData("TRACE_MAP_SIZE", SQLDataType.INTEGER, Integer.class, TRACE_MAP_SIZE_VAR),
          new ShredRowMetaData("JUMPED_ASSESS_CTX", SQLDataType.BOOLEAN, Boolean.class, JUMPED_ASSESS_CTX_VAR),
          new ShredRowMetaData("CHANNEL_HANDLER_CTX", SQLDataType.VARCHAR, String.class, CHANNEL_HANDLER_CTX_VAR),
          new ShredRowMetaData("HTTP_MSG", SQLDataType.VARCHAR, String.class, NETTY_HTTP_MSG_VAR),
          new ShredRowMetaData("DECODER_STATE", SQLDataType.VARCHAR, String.class, DECODER_STATE_VAR),
          new ShredRowMetaData("RESP", SQLDataType.VARCHAR, String.class, RESP_VAR),
          new ShredRowMetaData("APP_CTX", SQLDataType.VARCHAR, String.class, APP_CTX_VAR)
      );

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
  static final String ASSESS_NULL_XTRACTS = ASSESS_CTX_XTRACT + "(\\{)?\\}";
  static final String WITH_WRAPPED_RUNNABLE_XTRACT =  "\\) wrapping task " + WRAPPED_RUNNABLE_XTRACT+ " with ContrastContext";
  static final String WITHOUT_WRAPPED_RUNNABLE_XTRACT =  "\\) with ContrastContext";
  static final String START_CONTRAST_CONTEXT_EXTRACT = "ContrastContext\\{http=HttpContext\\{" + REQ_XTRACT + ", " + RESP_XTRACT + "\\}, uri='" + URL_XTRACT + "', assessment=";
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
                                      + " " + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NONNULL_XTRACTS
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_CHANNEL_XTRACT
                                      + NO_CHANNEL_HANDLER_CTX_XTRACT
                                      + NO_NETTY_HTTP_MSG_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "safeExecuteWrappingAssessNull",
                      List.of("- AbstractEventExecutor.safeExecute(", " wrapping task "),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- AbstractEventExecutor.safeExecute\\("
                                      + TASK_OBJ_XTRACT
                                      + WITH_WRAPPED_RUNNABLE_XTRACT
                                      + " " + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NULL_XTRACTS
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_CHANNEL_XTRACT
                                      + NO_CHANNEL_HANDLER_CTX_XTRACT
                                      + NO_NETTY_HTTP_MSG_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + NO_TRACE_MAP_XTRACT + NO_TRACE_MAP_SIZE_XTRACT + NO_JUMPED_ASSESS_CTX_XTRACT
                                      + "$")),
              new PatternMetadata(
              "safeExecuteAssessNonnull",
              List.of("- AbstractEventExecutor.safeExecute(", "{traceMap="),
              Pattern.compile(
                  DEBUG_PREAMBLE_XTRACT
                      + "- AbstractEventExecutor.safeExecute\\("
                      + TASK_OBJ_XTRACT
                      + WITHOUT_WRAPPED_RUNNABLE_XTRACT
                          + " " + START_CONTRAST_CONTEXT_EXTRACT
                          + ASSESS_NONNULL_XTRACTS
                          + NO_CONCUR_CTX_XTRACT
                      + NO_APP_CTX_XTRACT
                      + NO_TASK_CLASS_XTRACT
                      + NO_WRAP_INIT_XTRACT
                      + NO_WRAPPED_RUNNABLE_XTRACT
                          + NO_CHANNEL_XTRACT
                          + NO_CHANNEL_HANDLER_CTX_XTRACT
                          + NO_NETTY_HTTP_MSG_XTRACT
                          + NO_DECODER_STATE_XTRACT
                          + "$")),
              new PatternMetadata(
                      "safeExecuteAssessNull",
                      List.of("- AbstractEventExecutor.safeExecute("),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- AbstractEventExecutor.safeExecute\\("
                                      + TASK_OBJ_XTRACT
                                      + WITHOUT_WRAPPED_RUNNABLE_XTRACT
                                      + " " + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NULL_XTRACTS
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_CHANNEL_XTRACT
                                      + NO_NETTY_HTTP_MSG_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + NO_TRACE_MAP_XTRACT + NO_TRACE_MAP_SIZE_XTRACT + NO_JUMPED_ASSESS_CTX_XTRACT
                                      + NO_CHANNEL_HANDLER_CTX_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "fireChannelReadAssessNonnull",
                      List.of("- ContrastNettyHttpDispatcherImpl.onFireChannelRead(", "{traceMap="),
              Pattern.compile(
  DEBUG_PREAMBLE_XTRACT
                              + "- ContrastNettyHttpDispatcherImpl.onFireChannelRead\\("
                                      + START_CONTRAST_CONTEXT_EXTRACT
                              + ASSESS_NONNULL_XTRACTS
                              + ", " + CHANNEL_HANDLER_CTX_XTRACT + "\\) with channel "
                              + CHANNEL_XTRACT
                              + NO_CONCUR_CTX_XTRACT
                              + NO_APP_CTX_XTRACT
                              + NO_TASK_CLASS_XTRACT
                              + NO_WRAP_INIT_XTRACT
                              + NO_WRAPPED_RUNNABLE_XTRACT
          + NO_NETTY_HTTP_MSG_XTRACT
          + NO_DECODER_STATE_XTRACT
          + NO_TASK_OBJ_XTRACT
          + "$")),
              new PatternMetadata(
                      "fireChannelReadAssessNull",
                      List.of("- ContrastNettyHttpDispatcherImpl.onFireChannelRead("),
              Pattern.compile(
  DEBUG_PREAMBLE_XTRACT
                              + "- ContrastNettyHttpDispatcherImpl.onFireChannelRead\\("
                                      + START_CONTRAST_CONTEXT_EXTRACT
                              + ASSESS_NULL_XTRACTS
                              + ", " + CHANNEL_HANDLER_CTX_XTRACT + "\\) with channel "
          + CHANNEL_XTRACT
                              + NO_CONCUR_CTX_XTRACT
                              + NO_APP_CTX_XTRACT
                              + NO_TASK_CLASS_XTRACT
                              + NO_WRAP_INIT_XTRACT
                              + NO_WRAPPED_RUNNABLE_XTRACT
          + NO_NETTY_HTTP_MSG_XTRACT
          + NO_DECODER_STATE_XTRACT
          + NO_TRACE_MAP_XTRACT + NO_TRACE_MAP_SIZE_XTRACT + NO_JUMPED_ASSESS_CTX_XTRACT
          + NO_TASK_OBJ_XTRACT
          + "$")),
              new PatternMetadata(
                      "requestDecodedAssessNonnull",
                      List.of("- ContrastNettyHttpDispatcherImpl.onRequestDecoded(", "{traceMap="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- ContrastNettyHttpDispatcherImpl.onRequestDecoded\\("
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NONNULL_XTRACTS
                                      + ", " + CHANNEL_HANDLER_CTX_XTRACT
                                      + ", " + NETTY_HTTP_MSG_XTRACT
                                      + "\\) with channel "
                                      + CHANNEL_XTRACT + " and decoderState "
                                      + DECODER_STATE_XTRACT
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "requestDecodedAssessNull",
                      List.of("- ContrastNettyHttpDispatcherImpl.onRequestDecoded("),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- ContrastNettyHttpDispatcherImpl.onRequestDecoded\\("

                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NULL_XTRACTS
                                      + ", " + CHANNEL_HANDLER_CTX_XTRACT
                                      + ", " + NETTY_HTTP_MSG_XTRACT
                                      + "\\) with channel "
                                      + CHANNEL_XTRACT + " and decoderState "
                                      + DECODER_STATE_XTRACT
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + NO_TRACE_MAP_XTRACT + NO_TRACE_MAP_SIZE_XTRACT + NO_JUMPED_ASSESS_CTX_XTRACT
                                      + "$")),
              // 2024-11-19 18:57:23,606 [reactor-http-nio-3 ContrastNettyHttpDispatcherImpl] DEBUG - ContrastNettyHttpDispatcherImpl.onResponseWritten(
              //  ContrastContext{http=HttpContext{HttpRequest@0ec78ce2, null}, uri='/sources/v5_0/serverWebExchange-multipartData-file', assessment=AssessmentContext@496a99fc{traceMap=TraceMap@452706d3 (with 59 items in it), jumpedContexts=true}},
              //  io.netty.channel.CombinedChannelDuplexHandler$DelegatingChannelHandlerContext@36fc72e6,
              //  io.netty.handler.codec.http.DefaultFullHttpResponse@09b67079) with channel NioSocketChannel@14df230e
              new PatternMetadata(
                      "responseWrittenAssessNonnull",
                      List.of("- ContrastNettyHttpDispatcherImpl.onResponseWritten(", "{traceMap="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- ContrastNettyHttpDispatcherImpl.onResponseWritten\\("
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NONNULL_XTRACTS
                                      + ", " + CHANNEL_HANDLER_CTX_XTRACT
                                      + ", " + NETTY_HTTP_MSG_XTRACT
                                      + "\\) with channel "
                                      + CHANNEL_XTRACT
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "responseWrittenAssessNull",
                      List.of("- ContrastNettyHttpDispatcherImpl.onResponseWritten("),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- ContrastNettyHttpDispatcherImpl.onResponseWritten\\("
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NULL_XTRACTS
                                      + ", " + CHANNEL_HANDLER_CTX_XTRACT
                                      + ", " + NETTY_HTTP_MSG_XTRACT
                                      + "\\) with channel "
                                      + CHANNEL_XTRACT
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + NO_TRACE_MAP_XTRACT + NO_TRACE_MAP_SIZE_XTRACT + NO_JUMPED_ASSESS_CTX_XTRACT
                                      + "$"))
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
//          "2024-11-19 18:57:22,773 [reactor-http-nio-2 ContrastNettyHttpDispatcherImpl] DEBUG - ContrastNettyHttpDispatcherImpl.onRequestDecoded(ContrastContext{http=HttpContext{null, null}, uri='null', assessment=AssessmentContext@2012d51f{traceMap=TraceMap@5c377c22 (with 27 items in it), jumpedContexts=true}}, HttpServerRequestDecoder@703be535, DefaultHttpRequest@7067eec3) with channel NioSocketChannel@55ea0ec0 and decoderState READ_FIXED_LENGTH_CONTENT",
//          "2024-11-19 18:57:22,799 [reactor-http-nio-3 ContrastNettyHttpDispatcherImpl] DEBUG - ContrastNettyHttpDispatcherImpl.onRequestDecoded(ContrastContext{http=HttpContext{null, null}, uri='null', assessment=null{}, HttpServerRequestDecoder@2e6a8e10, DefaultHttpRequest@3ed207d3) with channel NioSocketChannel@52c17f46 and decoderState READ_FIXED_LENGTH_CONTENT",
//          "2024-11-19 18:57:23,606 [reactor-http-nio-3 ContrastNettyHttpDispatcherImpl] DEBUG - ContrastNettyHttpDispatcherImpl.onResponseWritten(ContrastContext{http=HttpContext{HttpRequest@0ec78ce2, null}, uri='/sources/v5_0/serverWebExchange-multipartData-file', assessment=AssessmentContext@496a99fc{traceMap=TraceMap@452706d3 (with 59 items in it), jumpedContexts=true}}, io.netty.channel.CombinedChannelDuplexHandler$DelegatingChannelHandlerContext@36fc72e6, io.netty.handler.codec.http.DefaultFullHttpResponse@09b67079) with channel NioSocketChannel@14df230e"
    "2024-11-19 19:50:51,850 [reactor-http-nio-2 b] DEBUG - ContrastNettyHttpDispatcherImpl.onRequestDecoded(ContrastContext{http=HttpContext{null, null}, uri='null', assessment=null}, HttpServerRequestDecoder@3764e20a, DefaultHttpRequest@0ab4ff90) with channel NioSocketChannel@69bd21e6 and decoderState SKIP_CONTROL_CHARS"
  );
  
  public static void main(String[] args) {
    testPatternMatching(exampleLogLines, PATTERN_METADATA, true);
  }
}
