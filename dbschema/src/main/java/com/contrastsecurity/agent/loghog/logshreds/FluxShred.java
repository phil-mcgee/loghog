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
import java.nio.channels.Channel;
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
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.WARN_PREAMBLE_XTRACT;
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
    "- ContrastNettyHttpDispatcherImpl.",
    "- Exiting ContrastNettyHttpDispatcherImpl.",
    "ing NioEventLoop.processSelectedKey(",
    "- NettyChannelContext."
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
  static final String WITH_WRAPPED_RUNNABLE_XTRACT =  "\\) wrapping task " + WRAPPED_RUNNABLE_XTRACT+ " deploying ";
  static final String WITHOUT_WRAPPED_RUNNABLE_XTRACT =  "\\) with";
  static final String START_CONTRAST_CONTEXT_EXTRACT = "ContrastContext\\{http=HttpContext\\{" + REQ_XTRACT + ", " + RESP_XTRACT + "\\}, uri='" + URL_XTRACT + "', assessment=";
  static final String SKIP_CONTRAST_CONTEXT = "ContrastContext\\{http=HttpContext\\{[^\\}]+\\}, uri='[^']+', assessment=(null|[^\\{]*\\{[^\\}]+\\})\\}";

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
                                      + START_CONTRAST_CONTEXT_EXTRACT
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
                              + ", " + CHANNEL_HANDLER_CTX_XTRACT + "\\) from handler "
                              + WRAP_INIT_XTRACT + " with channel " // I hijacked this field inappropriately
                              + CHANNEL_XTRACT
                              + NO_CONCUR_CTX_XTRACT
                              + NO_APP_CTX_XTRACT
                              + NO_TASK_CLASS_XTRACT
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
                              + ", " + CHANNEL_HANDLER_CTX_XTRACT + "\\) from handler "
                              + WRAP_INIT_XTRACT + " with channel " // I hijacked this field inappropriately
                              + CHANNEL_XTRACT
                              + NO_CONCUR_CTX_XTRACT
                              + NO_APP_CTX_XTRACT
                              + NO_TASK_CLASS_XTRACT
                              + NO_WRAPPED_RUNNABLE_XTRACT
                              + NO_NETTY_HTTP_MSG_XTRACT
                              + NO_DECODER_STATE_XTRACT
                              + NO_TRACE_MAP_XTRACT + NO_TRACE_MAP_SIZE_XTRACT + NO_JUMPED_ASSESS_CTX_XTRACT
                              + NO_TASK_OBJ_XTRACT
                              + "$")),
              new PatternMetadata(
                      "channelFlushAssessNonnull",
                      List.of("- ContrastNettyHttpDispatcherImpl.onFlush(", "{traceMap="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- ContrastNettyHttpDispatcherImpl.onFlush\\("
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NONNULL_XTRACTS
                                      + ", " + CHANNEL_HANDLER_CTX_XTRACT + "\\) from handler "
                                      + WRAP_INIT_XTRACT + " with channel " // I hijacked this field inappropriately
                                      + CHANNEL_XTRACT
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_NETTY_HTTP_MSG_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "channelFlushAssessNull",
                      List.of("- ContrastNettyHttpDispatcherImpl.onFlush("),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- ContrastNettyHttpDispatcherImpl.onFlush\\("
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NULL_XTRACTS
                                      + ", " + CHANNEL_HANDLER_CTX_XTRACT + "\\) from handler "
                                      + WRAP_INIT_XTRACT + " with channel " // I hijacked this field inappropriately
                                      + CHANNEL_XTRACT
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_NETTY_HTTP_MSG_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + NO_TRACE_MAP_XTRACT + NO_TRACE_MAP_SIZE_XTRACT + NO_JUMPED_ASSESS_CTX_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "requestDecodedAssessNonnull",
                      List.of("- Exiting ContrastNettyHttpDispatcherImpl.onRequestDecoded(", "{traceMap="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- Exiting ContrastNettyHttpDispatcherImpl.onRequestDecoded\\("
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NONNULL_XTRACTS
                                      + ", " + CHANNEL_HANDLER_CTX_XTRACT
                                      + ", " + NETTY_HTTP_MSG_XTRACT
                                      + "\\) with channel "+ CHANNEL_XTRACT
                                      + " decoderState " + DECODER_STATE_XTRACT
//  FIXME                                     + " and channelContext  .+"
                                      + " and .+"
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "requestDecodedAssessNull",
                      List.of("- Exiting ContrastNettyHttpDispatcherImpl.onRequestDecoded(", "ContrastContext{http="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- Exiting ContrastNettyHttpDispatcherImpl.onRequestDecoded\\("
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NULL_XTRACTS
                                      + ", " + CHANNEL_HANDLER_CTX_XTRACT
                                      + ", " + NETTY_HTTP_MSG_XTRACT
                                      + "\\) with channel "+ CHANNEL_XTRACT
                                      + " decoderState " + DECODER_STATE_XTRACT
//  FIXME                                     + " and channelContext  .+"
                                      + " and .+"
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + NO_TRACE_MAP_XTRACT + NO_TRACE_MAP_SIZE_XTRACT + NO_JUMPED_ASSESS_CTX_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "WarnOnResponseWrittenAssessNonnull",
                      List.of("DEBUG - ContrastNettyHttpDispatcherImpl.onResponseWritten(",  "{traceMap=", "found null Channel incoming and outgoing contexts"),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- ContrastNettyHttpDispatcherImpl.onResponseWritten\\("
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NONNULL_XTRACTS + ", "
                                      + CHANNEL_HANDLER_CTX_XTRACT + ", "
                                      + NETTY_HTTP_MSG_XTRACT + "\\) with channel "
                                      + CHANNEL_XTRACT
                                      + " found null Channel incoming and outgoing contexts, so continuing with ContrastContext from thread\\."
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "WarnOnResponseWrittenAssessNull",
                      List.of("DEBUG - ContrastNettyHttpDispatcherImpl.onResponseWritten(", "ContrastContext{http=", "found null Channel incoming and outgoing contexts"),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- ContrastNettyHttpDispatcherImpl.onResponseWritten\\("
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NULL_XTRACTS + ", "
                                      + CHANNEL_HANDLER_CTX_XTRACT + ", "
                                      + NETTY_HTTP_MSG_XTRACT
                                      + "\\) with channel "
                                      + CHANNEL_XTRACT
                                      + " found null Channel incoming and outgoing contexts, so continuing with ContrastContext from thread\\."                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + NO_TRACE_MAP_XTRACT + NO_TRACE_MAP_SIZE_XTRACT + NO_JUMPED_ASSESS_CTX_XTRACT
                                      + "$")),
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
                      List.of("DEBUG - ContrastNettyHttpDispatcherImpl.onResponseWritten(", "with channel"),
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
                                      + "$")),
              new PatternMetadata(
                      "copyIncomingToOutgoingAssessNonnull",
                      List.of("- NettyChannelContext.copyChannelIncomingToOutgoing(", "{traceMap="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- NettyChannelContext.copyChannelIncomingToOutgoing\\("
                                      + CHANNEL_XTRACT
                                      + "\\) copied channel incoming "
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NONNULL_XTRACTS
                                      + " to channel outgoing att, replacing .+"
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + NO_CHANNEL_HANDLER_CTX_XTRACT
                                      + NO_NETTY_HTTP_MSG_XTRACT
                                       + "$")),
              new PatternMetadata(
                      "copyIncomingToOutgoingAssessNull",
                      List.of("- NettyChannelContext.copyChannelIncomingToOutgoing(", "incoming attr ContrastContext{http="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- NettyChannelContext.copyChannelIncomingToOutgoing\\("
                                      + CHANNEL_XTRACT
                                      + "\\) copied channel incoming "
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NULL_XTRACTS
                                      + " to channel outgoing att, replacing .+"
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + NO_TRACE_MAP_XTRACT + NO_TRACE_MAP_SIZE_XTRACT + NO_JUMPED_ASSESS_CTX_XTRACT
                                      + NO_CHANNEL_HANDLER_CTX_XTRACT
                                      + NO_NETTY_HTTP_MSG_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "copyIncomingToOutgoingCCtxNull",
                      List.of("- NettyChannelContext.copyChannelIncomingToOutgoing(", "incoming null "),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- NettyChannelContext.copyChannelIncomingToOutgoing\\("
                                      + CHANNEL_XTRACT
                                      + "\\) copied channel incoming null to channel outgoing att, replacing .+"
                                      // NettyChannelContext.copyChannelIncomingToOutgoing(
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + NO_ASSESS_CTX_XTRACT
                                      + NO_TRACE_MAP_XTRACT + NO_TRACE_MAP_SIZE_XTRACT + NO_JUMPED_ASSESS_CTX_XTRACT
                                      + NO_REQ_XTRACT + NO_RESP_XTRACT + NO_URL_XTRACT
                                      + NO_CHANNEL_HANDLER_CTX_XTRACT
                                      + NO_NETTY_HTTP_MSG_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "nullifyChannelAttrAssessNonnull",
                      List.of("- NettyChannelContext.nullifyChannelContext(", "{traceMap="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- NettyChannelContext.nullifyChannelContext\\("
                                      + CHANNEL_XTRACT + ", " + "(INCOMING|OUTGOING)"  // FIXME
                                      + "\\) replacing "
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NONNULL_XTRACTS
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + NO_CHANNEL_HANDLER_CTX_XTRACT
                                      + NO_NETTY_HTTP_MSG_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "nullifyChannelAttrCCtxNonnull",
                      List.of("- NettyChannelContext.nullifyChannelContext(", "ContrastContext{http="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- NettyChannelContext.nullifyChannelContext\\("
                                      + CHANNEL_XTRACT + ", " + "(INCOMING|OUTGOING)"  // FIXME
                                      + "\\) replacing "
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NULL_XTRACTS
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + NO_TRACE_MAP_XTRACT + NO_TRACE_MAP_SIZE_XTRACT + NO_JUMPED_ASSESS_CTX_XTRACT
                                      + NO_CHANNEL_HANDLER_CTX_XTRACT
                                      + NO_NETTY_HTTP_MSG_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "nullifyChannelAttrCCtxNull",
                      List.of("- NettyChannelContext.nullifyChannelContext(", "replacing null"),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- NettyChannelContext.nullifyChannelContext\\("
                                      + CHANNEL_XTRACT + ", " + "(INCOMING|OUTGOING)"  // FIXME
                                      + "\\) replacing null"
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + NO_ASSESS_CTX_XTRACT
                                      + NO_TRACE_MAP_XTRACT + NO_TRACE_MAP_SIZE_XTRACT + NO_JUMPED_ASSESS_CTX_XTRACT
                                      + NO_REQ_XTRACT + NO_RESP_XTRACT + NO_URL_XTRACT
                                      + NO_CHANNEL_HANDLER_CTX_XTRACT
                                      + NO_NETTY_HTTP_MSG_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "updateChannelIncomingAssessNonnull",
                      List.of("- NettyChannelContext.updateChannelIncomingContrastContext(", "{traceMap="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- NettyChannelContext.updateChannelIncomingContrastContext\\("
                                      + CHANNEL_XTRACT + ", "
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NONNULL_XTRACTS
                                      + "\\) saved channel incoming attr, replacing .+"
//                                      + ".+"
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + NO_CHANNEL_HANDLER_CTX_XTRACT
                                      + NO_NETTY_HTTP_MSG_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "updateChannelIncomingAssessNull",
                      List.of("- NettyChannelContext.updateChannelIncomingContrastContext(", "ContrastContext{http="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- NettyChannelContext.updateChannelIncomingContrastContext\\("
                                      + CHANNEL_XTRACT + ", "
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NULL_XTRACTS
                                      + "\\) saved channel incoming attr, replacing .+"
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + NO_TRACE_MAP_XTRACT + NO_TRACE_MAP_SIZE_XTRACT + NO_JUMPED_ASSESS_CTX_XTRACT
                                      + NO_CHANNEL_HANDLER_CTX_XTRACT
                                      + NO_NETTY_HTTP_MSG_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "updateCurrentCCtxAssessNonnull",
                      List.of("DEBUG - ContrastNettyHttpDispatcherImpl.updateCurrentContrastContextFromChannel(", "{traceMap="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- ContrastNettyHttpDispatcherImpl.updateCurrentContrastContextFromChannel\\("
                                      + CHANNEL_XTRACT + ", "
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NONNULL_XTRACTS
                                      + ", [^)]+\\) replacing .+"
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + NO_CHANNEL_HANDLER_CTX_XTRACT
                                      + NO_NETTY_HTTP_MSG_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "updateCurrentCCtxAssessNull",
                      List.of("DEBUG - ContrastNettyHttpDispatcherImpl.updateCurrentContrastContextFromChannel(", "ContrastContext{http="),
                      Pattern.compile(
                              WARN_PREAMBLE_XTRACT
                                      + "- ContrastNettyHttpDispatcherImpl.updateCurrentContrastContextFromChannel\\("
                                      + CHANNEL_XTRACT + ", "
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NULL_XTRACTS
                                      + ", [^)]+\\) replacing .+"
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + NO_TRACE_MAP_XTRACT + NO_TRACE_MAP_SIZE_XTRACT + NO_JUMPED_ASSESS_CTX_XTRACT
                                      + NO_CHANNEL_HANDLER_CTX_XTRACT
                                      + NO_NETTY_HTTP_MSG_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "UpdateCCtxFromChannelAssessNonnull",
                      List.of("DEBUG - NettyChannelContext.updateContextFromChannel(",  "{traceMap="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- NettyChannelContext.updateContextFromChannel\\("
                                      + CHANNEL_XTRACT + ", "
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NONNULL_XTRACTS
                                      + ", [^)]+\\) replacing .+"
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + NO_CHANNEL_HANDLER_CTX_XTRACT
                                      + NO_NETTY_HTTP_MSG_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "WarnUpdateCCtxFromChannelAssessNull",
                      List.of("WARN - NettyChannelContext.updateContextFromChannel(", "ContrastContext{http="),
                      Pattern.compile(
                              WARN_PREAMBLE_XTRACT
                                      + "- NettyChannelContext.updateContextFromChannel\\("
                                      + CHANNEL_XTRACT + ", "
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NULL_XTRACTS
                                      + ", [^)]+\\) retieved null ContrastContext from channel.  Leaving current ContrastContext as is\\."
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + NO_TRACE_MAP_XTRACT + NO_TRACE_MAP_SIZE_XTRACT + NO_JUMPED_ASSESS_CTX_XTRACT
                                      + NO_CHANNEL_HANDLER_CTX_XTRACT
                                      + NO_NETTY_HTTP_MSG_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "EnterProcessSelectedKeyAssessNonnull",
                      List.of("- Entering NioEventLoop.processSelectedKey(",  "{traceMap="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- Entering NioEventLoop.processSelectedKey\\("
                                      + "[^,]+, "
                                      + CHANNEL_XTRACT + "\\) with "
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NONNULL_XTRACTS
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + NO_CHANNEL_HANDLER_CTX_XTRACT
                                      + NO_NETTY_HTTP_MSG_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "EnterProcessSelectedKeyAssessNull",
                      List.of("- Entering NioEventLoop.processSelectedKey(", "ContrastContext{http="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- Entering NioEventLoop.processSelectedKey\\("
                                      + "[^,]+, "
                                      + CHANNEL_XTRACT + "\\) with "
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NULL_XTRACTS
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + NO_CHANNEL_HANDLER_CTX_XTRACT
                                      + NO_NETTY_HTTP_MSG_XTRACT
                                      + NO_TRACE_MAP_XTRACT + NO_TRACE_MAP_SIZE_XTRACT + NO_JUMPED_ASSESS_CTX_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "ExitProcessSelectedKeyAssessNonnull",
                      List.of("- Exiting NioEventLoop.processSelectedKey(",  "{traceMap="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- Exiting NioEventLoop.processSelectedKey\\("
                                      + "[^,]+, "
                                      + CHANNEL_XTRACT + "\\) with "
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NONNULL_XTRACTS
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + NO_CHANNEL_HANDLER_CTX_XTRACT
                                      + NO_NETTY_HTTP_MSG_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "ExitProcessSelectedKeyAssessNull",
                      List.of("- Exiting NioEventLoop.processSelectedKey(", "ContrastContext{http="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- Exiting NioEventLoop.processSelectedKey\\("
                                      + "[^,]+, "
                                      + CHANNEL_XTRACT + "\\) with "
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NULL_XTRACTS
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + NO_CHANNEL_HANDLER_CTX_XTRACT
                                      + NO_NETTY_HTTP_MSG_XTRACT
                                      + NO_TRACE_MAP_XTRACT + NO_TRACE_MAP_SIZE_XTRACT + NO_JUMPED_ASSESS_CTX_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "responseWrittenUnexpectedMessage",
                      List.of("- ContrastNettyHttpDispatcherImpl.onResponseWritten() found unexpected message"),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- ContrastNettyHttpDispatcherImpl.onResponseWritten\\(\\) found unexpected message "
                                      + NETTY_HTTP_MSG_XTRACT
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_ASSESS_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + NO_URL_XTRACT
                                      + NO_DECODER_STATE_XTRACT
                                      + NO_CHANNEL_XTRACT
                                      + NO_CHANNEL_HANDLER_CTX_XTRACT
                                      + NO_REQ_XTRACT
                                      + NO_RESP_XTRACT
                                      + NO_TRACE_MAP_XTRACT + NO_TRACE_MAP_SIZE_XTRACT + NO_JUMPED_ASSESS_CTX_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "invalidDecodedStateNullCCtx",
                      List.of("- ContrastNettyHttpDispatcherImpl.onRequestDecoded()", "found invalid state with incoming channel context"),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- ContrastNettyHttpDispatcherImpl.onRequestDecoded\\(\\) found invalid state with incoming channel context "
                                      + "null"    // FIXME
                                      + " message "
                                      + NETTY_HTTP_MSG_XTRACT
                                      + " decoderState "
                                      + DECODER_STATE_XTRACT
                                      + " with channel "
                                      + CHANNEL_XTRACT
                                      + NO_CONCUR_CTX_XTRACT
                                      + NO_APP_CTX_XTRACT
                                      + NO_ASSESS_CTX_XTRACT
                                      + NO_TASK_CLASS_XTRACT
                                      + NO_WRAP_INIT_XTRACT
                                      + NO_WRAPPED_RUNNABLE_XTRACT
                                      + NO_TASK_OBJ_XTRACT
                                      + NO_URL_XTRACT
                                      + NO_CHANNEL_HANDLER_CTX_XTRACT
                                      + NO_REQ_XTRACT
                                      + NO_RESP_XTRACT
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
    super(SHRED_METADATA, SHRED_SQL_TABLE, MISFITS_METADATA, MISFITS_SQL_TABLE, SHRED_SOURCE, true);
  }

  static final List<String> exampleLogLines = List.of(
//          "2024-12-01 23:03:58,997 [main ContrastPolicy] DEBUG - ContrastNettyHttpDispatcherImpl.moveChannelIncomingContrastContextToOutgoing(NioSocketChannel@101cd7af) moved channel incoming attr ContrastContext{http=HttpContext{HttpRequest@7b4ddd9d, null}, uri='/sources/v5_0/serverHttpRequest-headers', assessment=AssessmentContext@0e70d780{traceMap=b@2a1a4394 (with 37 items in it), jumpedContexts=true}} to channel outgoing att, replacing null",
//          "2024-12-01 23:03:58,997 [main ContrastPolicy] DEBUG - ContrastNettyHttpDispatcherImpl.moveChannelIncomingContrastContextToOutgoing(NioSocketChannel@279e3881) moved channel incoming attr null to channel outgoing att, replacing null",
//          "2024-12-01 23:03:58,997 [main ContrastPolicy] DEBUG - ContrastNettyHttpDispatcherImpl.nullifyChannelOutgoingContrastContext(NioSocketChannel@279e3881) removed channel outgoing ContrastContext null",
//          "2024-12-01 23:03:58,997 [main ContrastPolicy] DEBUG - ContrastNettyHttpDispatcherImpl.nullifyChannelOutgoingContrastContext(NioSocketChannel@101cd7af) removed channel outgoing ContrastContext ContrastContext{http=HttpContext{HttpRequest@7b4ddd9d, null}, uri='/sources/v5_0/serverHttpRequest-headers', assessment=AssessmentContext@0e70d780{traceMap=b@2a1a4394 (with 37 items in it), jumpedContexts=true}}",
//          "2024-12-01 23:03:58,997 [main ContrastPolicy] DEBUG - ContrastNettyHttpDispatcherImpl.updateChannelIncomingContrastContext(NioSocketChannel@101cd7af, ContrastContext{http=HttpContext{HttpRequest@7b4ddd9d, null}, uri='/sources/v5_0/serverHttpRequest-headers', assessment=AssessmentContext@0e70d780{traceMap=b@2a1a4394 (with 0 items in it), jumpedContexts=false}}) saved channel incoming attr, replacing null",
//          "2024-12-01 23:03:58,997 [main ContrastPolicy] DEBUG - ContrastNettyHttpDispatcherImpl.updateCurrentContrastContextFromChannel(NioSocketChannel@101cd7af, ContrastContext{http=HttpContext{HttpRequest@7b4ddd9d, null}, uri='/sources/v5_0/serverHttpRequest-headers', assessment=AssessmentContext@0e70d780{traceMap=b@2a1a4394 (with 37 items in it), jumpedContexts=true}}, AttributeKey@5c1c2aa2) replacing ContrastContext{http=HttpContext{HttpRequest@7b4ddd9d, null}, uri='/sources/v5_0/serverHttpRequest-headers', assessment=AssessmentContext@0e70d780{traceMap=b@2a1a4394 (with 37 items in it), jumpedContexts=true}}",
//          "2024-12-02 20:31:22,215 [reactor-http-nio-2 b] WARN - ContrastNettyHttpDispatcherImpl.updateCurrentContrastContextFromChannel(NioSocketChannel@34aef235, ContrastContext{http=HttpContext{null, null}, uri='null', assessment=null}, AttributeKey@39128da0) retieved null ContrastContext from channel.  Leaving current ContrastContext as is.",
//          "2024-12-02 20:31:22,373 [reactor-http-nio-2 b] WARN - ContrastNettyHttpDispatcherImpl.onResponseWritten(ContrastContext{http=HttpContext{null, null}, uri='null', assessment=null}, DelegatingChannelHandlerContext@3b4427f6, DefaultFullHttpResponse@151844e4) with channel NioSocketChannel@34aef235 found null Channel incoming and outgoing contexts, so continuing with ContrastContext from thread.",
//          "2024-12-02 20:31:22,052 [reactor-http-nio-1 b] DEBUG - Entering NioEventLoop.processSelectedKey(sun.nio.ch.SelectionKeyImpl@2d12d504, io.netty.channel.socket.nio.NioServerSocketChannel@15417052) with ContrastContext{http=HttpContext{null, null}, uri='null', assessment=null}",
//          "2024-12-02 20:31:22,069 [reactor-http-nio-1 b] DEBUG - Exiting NioEventLoop.processSelectedKey(sun.nio.ch.SelectionKeyImpl@2d12d504, io.netty.channel.socket.nio.NioServerSocketChannel@15417052) with ContrastContext{http=HttpContext{null, null}, uri='null', assessment=null}",
//          "2024-12-09 18:52:53,104 [reactor-http-nio-2 b] DEBUG - Exiting ContrastNettyHttpDispatcherImpl.onRequestDecoded(ContrastContext{http=HttpContext{null, null}, uri='null', assessment=null}, HttpServerRequestDecoder@6f6dba9f, DefaultHttpRequest@5f53c7dd) with channel NioSocketChannel@2e98c6aa decoderState SKIP_CONTROL_CHARS and ContrastContext{http=HttpContext{null, null}, uri='null', assessment=null}",
//          "2024-12-11 22:41:24,394 [reactor-http-nio-2 ContrastNettyHttpDispatcherImpl] DEBUG - ContrastNettyHttpDispatcherImpl.onResponseWritten(ContrastContext{http=HttpContext{HttpRequest@5002ff07, null}, uri='/routecoverage/annotation/', assessment=AssessmentContext@16b9d1d2{traceMap=TraceMap@3ed3b7bd (with 70 items in it), jumpedContexts=true}}, DelegatingChannelHandlerContext@7d2d2cac, DefaultFullHttpResponse@5900f874) with channel NioSocketChannel@209969be found null Channel incoming and outgoing contexts, so continuing with ContrastContext from thread.\n" +
//  "2024-12-11 22:41:24,458 [reactor-http-nio-2 NettyChannelContext] DEBUG - NettyChannelContext.updateChannelIncomingContrastContext(NioSocketChannel@209969be, ContrastContext{http=HttpContext{HttpRequest@0cd5566d, null}, uri='/routecoverage/annotation/', assessment=AssessmentContext@3010e784{traceMap=TraceMap@58fcf37d (with 0 items in it), jumpedContexts=true}}) saved channel incoming attr, replacing null",
//  "2024-12-11 22:41:24,472 [reactor-http-nio-2 NettyChannelContext] DEBUG - NettyChannelContext.updateContextFromChannel(NioSocketChannel@209969be, ContrastContext{http=HttpContext{HttpRequest@0cd5566d, null}, uri='/routecoverage/annotation/', assessment=AssessmentContext@3010e784{traceMap=TraceMap@58fcf37d (with 31 items in it), jumpedContexts=true}}, INCOMING) replacing ContrastContext{http=HttpContext{HttpRequest@0cd5566d, null}, uri='/routecoverage/annotation/', assessment=AssessmentContext@3010e784{traceMap=TraceMap@58fcf37d (with 31 items in it), jumpedContexts=true}}",
//  "2024-12-11 22:41:24,472 [reactor-http-nio-2 NettyChannelContext] DEBUG - NettyChannelContext.copyChannelIncomingToOutgoing(NioSocketChannel@209969be) copied channel incoming ContrastContext{http=HttpContext{HttpRequest@0cd5566d, null}, uri='/routecoverage/annotation/', assessment=AssessmentContext@3010e784{traceMap=TraceMap@58fcf37d (with 31 items in it), jumpedContexts=true}} to channel outgoing att, replacing ContrastContext{http=HttpContext{HttpRequest@0cd5566d, null}, uri='/routecoverage/annotation/', assessment=AssessmentContext@3010e784{traceMap=TraceMap@58fcf37d (with 31 items in it), jumpedContexts=true}}",
//  "2024-12-11 22:41:24,487 [reactor-http-nio-2 NettyChannelContext] DEBUG - NettyChannelContext.nullifyChannelContext(NioSocketChannel@209969be, INCOMING) replacing ContrastContext{http=HttpContext{HttpRequest@0cd5566d, null}, uri='/routecoverage/annotation/', assessment=AssessmentContext@3010e784{traceMap=TraceMap@58fcf37d (with 48 items in it), jumpedContexts=true}}",
//  "2024-12-11 22:41:24,487 [reactor-http-nio-2 NettyChannelContext] WARN - NettyChannelContext.updateCurrentContrastContextFromChannel(NioSocketChannel@209969be, ContrastContext{http=HttpContext{HttpRequest@0cd5566d, null}, uri='/routecoverage/annotation/', assessment=AssessmentContext@3010e784{traceMap=TraceMap@58fcf37d (with 48 items in it), jumpedContexts=true}}, INCOMING) retieved null ContrastContext from channel.  Leaving current ContrastContext as is."
//          "2024-12-12 15:08:45,760 [reactor-http-nio-2 NettyChannelContext] WARN - NettyChannelContext.updateContextFromChannel(NioSocketChannel@66814be9, ContrastContext{http=HttpContext{null, null}, uri='null', assessment=null}, INCOMING) retieved null ContrastContext from channel.  Leaving current ContrastContext as is."
//          "2024-12-13 15:09:54,817 [reactor-http-nio-2 b] DEBUG - Exiting ContrastNettyHttpDispatcherImpl.onRequestDecoded(ContrastContext{http=HttpContext{HttpRequest@1d3e95ef, null}, uri='/ping', assessment=AssessmentContext@7d1949c9{traceMap=b@01eee868 (with 0 items in it), jumpedContexts=true}}, HttpServerRequestDecoder@6d16d6a6, DefaultHttpRequest@031b95f5) with channel NioSocketChannel@207ac018 decoderState SKIP_CONTROL_CHARS and null"
//          "2024-12-13 15:09:55,121 [reactor-http-nio-2 b] DEBUG - Exiting ContrastNettyHttpDispatcherImpl.onRequestDecoded(ContrastContext{http=HttpContext{HttpRequest@5159d481, null}, uri='/client/v5_0/entity-headers', assessment=AssessmentContext@047a5fac{traceMap=b@5745553a (with 0 items in it), jumpedContexts=true}}, HttpServerRequestDecoder@42933174, DefaultHttpRequest@59edd928) with channel NioSocketChannel@4610b4e7 decoderState SKIP_CONTROL_CHARS and null"
          "2024-12-13 15:09:55,205 [reactor-http-nio-2 b] DEBUG - ContrastNettyHttpDispatcherImpl.onResponseWritten() found unexpected message io.netty.handler.codec.http.DefaultHttpRequest@636032f2"
  );

  public static void main(String[] args) {
    testPatternMatching(exampleLogLines, PATTERN_METADATA.stream().filter(pmd -> pmd.patternId().startsWith("responseWrittenUnexpectedMessage")).toList(), true);
  }
}
