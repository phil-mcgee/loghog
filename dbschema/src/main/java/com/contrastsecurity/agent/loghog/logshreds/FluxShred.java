/* (C)2024 */
package com.contrastsecurity.agent.loghog.logshreds;

import com.contrastsecurity.agent.loghog.shred.PatternMetadata;
import com.contrastsecurity.agent.loghog.shred.pmd.PmdShred;
import com.contrastsecurity.agent.loghog.shred.ShredRowMetaData;
import com.contrastsecurity.agent.loghog.shred.impl.ShredSqlTable;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import static com.contrastsecurity.agent.loghog.db.EmbeddedDatabaseFactory.jooq;
import static com.contrastsecurity.agent.loghog.db.LogTable.LOG_TABLE_NAME;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.APP_CTX_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.ASSESS_CTX_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.ASSESS_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.CHANNEL_HANDLER_CTX_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.CHANNEL_HANDLER_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.CHANNEL_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.CHANNEL_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.DEBUG_PREAMBLE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.DECODER_STATE_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.DECODER_STATE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.ERROR_PREAMBLE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.JUMPED_ASSESS_CTX_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.JUMPED_ASSESS_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NETTY_HTTP_MSG_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NETTY_HTTP_MSG_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.REQ_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.REQ_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.RESP_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.RESP_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TASK_CLASS_VAR;
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

public class FluxShred extends PmdShred {

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
              "LINE", SQLDataType.INTEGER.notNull(), Integer.class, LOG_TABLE_LINE_COL),
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

  public static final Set<String> ENTRY_SIGNATURES = Set.of(
          "- AbstractEventExecutor.safeExecute(",
          "- ContrastNettyHttpDispatcherImpl.",
          "- Exiting ContrastNettyHttpDispatcherImpl.",
          "ing NioEventLoop.processSelectedKey(",
          "- NettyChannelContext.");


  static final String ASSESS_NONNULL_XTRACTS = ASSESS_CTX_XTRACT + "\\{traceMap="
          + TRACE_MAP_XTRACT + " \\(with " + TRACE_MAP_SIZE_XTRACT + " items in it\\), jumpedContexts=" + JUMPED_ASSESS_CTX_XTRACT + "}}";
  static final String ASSESS_NULL_XTRACTS = ASSESS_CTX_XTRACT + "(\\{)?}";
  static final String WITH_WRAPPED_RUNNABLE_XTRACT =  "\\) wrapping task " + WRAPPED_RUNNABLE_XTRACT+ " with ContrastContext ";
  static final String WITHOUT_WRAPPED_RUNNABLE_XTRACT =  "\\) with ContrastContext";
  static final String START_CONTRAST_CONTEXT_EXTRACT = "ContrastContext\\{http=HttpContext\\{" + REQ_XTRACT + ", " + RESP_XTRACT + "}, uri='" + URL_XTRACT + "', assessment=";
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
                                      + "$")),
              new PatternMetadata(
                      "fireChannelReadAssessNonnull",
                      List.of("- ContrastNettyHttpDispatcherImpl.onFireChannelRead(", "{traceMap="),
              Pattern.compile(
                    DEBUG_PREAMBLE_XTRACT
                              + "- ContrastNettyHttpDispatcherImpl.onFireChannelRead\\("
                              + START_CONTRAST_CONTEXT_EXTRACT
                              + ASSESS_NONNULL_XTRACTS
                              + ", " + CHANNEL_HANDLER_CTX_XTRACT
                              + "\\) with channel " // I hijacked this field inappropriately
                              + CHANNEL_XTRACT
                              + " and pipeline .+"
                              + "$")),
            new PatternMetadata(
                      "fireChannelReadAssessNull",
                      List.of("- ContrastNettyHttpDispatcherImpl.onFireChannelRead("),
              Pattern.compile(
                    DEBUG_PREAMBLE_XTRACT
                              + "- ContrastNettyHttpDispatcherImpl.onFireChannelRead\\("
                                      + START_CONTRAST_CONTEXT_EXTRACT
                              + ASSESS_NULL_XTRACTS
                              + ", " + CHANNEL_HANDLER_CTX_XTRACT
                              + "\\) with channel "
                            + CHANNEL_XTRACT
                            + " and pipeline .+"
                            + "$")),
              new PatternMetadata(
                      "channelWriteCompleteAssessNonnull",
                      List.of("- ContrastNettyHttpDispatcherImpl.onChannelWriteComplete(", "{traceMap="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- ContrastNettyHttpDispatcherImpl.onChannelWriteComplete\\("
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NONNULL_XTRACTS
                                      + ", " + CHANNEL_XTRACT + "\\)"
                                      + "$")),
              new PatternMetadata(
                      "channelWriteCompleteAssessNull",
                      List.of("- ContrastNettyHttpDispatcherImpl.onChannelWriteComplete("),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- ContrastNettyHttpDispatcherImpl.onChannelWriteComplete\\("
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NULL_XTRACTS
                                      + ", " + CHANNEL_XTRACT + "\\)"
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
                                      + "\\) with channel "+ CHANNEL_XTRACT
                                      + " pipeline [^\\s]+"
                                      + " and decoderState " + DECODER_STATE_XTRACT
                                      + "$")),
              new PatternMetadata(
                      "requestDecodedAssessNull",
                      List.of("- ContrastNettyHttpDispatcherImpl.onRequestDecoded(", "ContrastContext{http="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- ContrastNettyHttpDispatcherImpl.onRequestDecoded\\("
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NULL_XTRACTS
                                      + ", " + CHANNEL_HANDLER_CTX_XTRACT
                                      + ", " + NETTY_HTTP_MSG_XTRACT
                                      + "\\) with channel "+ CHANNEL_XTRACT
                                      + " pipeline [^\\s]+"
                                      + " and decoderState " + DECODER_STATE_XTRACT
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
                                      + "$")),
              new PatternMetadata(
                      "WarnOnResponseWrittenAssessNull",
                      List.of("DEBUG - ContrastNettyHttpDispatcherImpl.onResponseWritten(", "{traceMap=", "found null Channel incoming and outgoing contexts"),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- ContrastNettyHttpDispatcherImpl.onResponseWritten\\("
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NULL_XTRACTS + ", "
                                      + CHANNEL_HANDLER_CTX_XTRACT + ", "
                                      + NETTY_HTTP_MSG_XTRACT
                                      + "\\) with channel "
                                      + CHANNEL_XTRACT
                                      + " found null Channel incoming and outgoing contexts, so continuing with ContrastContext from thread\\."
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
                                      + " and pipeline [^\\s]+"
                                      + "$")),
              new PatternMetadata(
                      "responseWrittenAssessNull",
                      List.of("- ContrastNettyHttpDispatcherImpl.onResponseWritten(ContrastContext{http="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- ContrastNettyHttpDispatcherImpl.onResponseWritten\\("
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NULL_XTRACTS
                                      + ", " + CHANNEL_HANDLER_CTX_XTRACT
                                      + ", " + NETTY_HTTP_MSG_XTRACT
                                      + "\\) with channel "
                                      + CHANNEL_XTRACT
                                      + " and pipeline [^\\s]+"
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
                                      + "$")),
              new PatternMetadata(
                      "nullifyChannelAttrCCtxNull",
                      List.of("- NettyChannelContext.nullifyChannelContext(", "replacing null"),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- NettyChannelContext.nullifyChannelContext\\("
                                      + CHANNEL_XTRACT + ", " + "(INCOMING|OUTGOING)"  // FIXME
                                      + "\\) replacing null"
                                      + "$")),
              new PatternMetadata(
                      "updateChannelContextAssessNonnull",
                      List.of("- NettyChannelContext.updateChannelContext(", "{traceMap="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- NettyChannelContext.updateChannelContext\\("
                                      + CHANNEL_XTRACT + ", "
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NONNULL_XTRACTS + ", "
                                      + "(INCOMING|OUTGOING)"
                                      + "\\) replacing .+"
                                      + "$")),
              new PatternMetadata(
                      "updateChannelContextAssessNull",
                      List.of("- NettyChannelContext.updateChannelIncomingContrastContext(", "ContrastContext{http="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- NettyChannelContext.updateChannelContext\\("
                                      + CHANNEL_XTRACT + ", "
                                      + START_CONTRAST_CONTEXT_EXTRACT
                                      + ASSESS_NULL_XTRACTS + ", "
                                      + "(INCOMING|OUTGOING)"
                                      + "\\) replacing .+"
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
                                      + "$")),
              new PatternMetadata(
                      "EnterProcessSelectedKeyAssessNonnull",
                      List.of("- Entering NioEventLoop.processSelectedKey(",  "{traceMap="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- Entering NioEventLoop.processSelectedKey\\("
                                      + "[^,]+, "
                                      + CHANNEL_XTRACT + "\\) using .+"
                                      + "$")),
              new PatternMetadata(
                      "EnterProcessSelectedKeyAssessNull",
                      List.of("- Entering NioEventLoop.processSelectedKey(", "ContrastContext{http="),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- Entering NioEventLoop.processSelectedKey\\("
                                      + "[^,]+, "
                                      + CHANNEL_XTRACT + "\\) using .+"
//                                      + START_CONTRAST_CONTEXT_EXTRACT
//                                      + ASSESS_NULL_XTRACTS
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
                                      + "$"))
      );

  public FluxShred() {
    super(SHRED_METADATA, SHRED_SQL_TABLE,
            MISFITS_METADATA, MISFITS_SQL_TABLE,
            ENTRY_SIGNATURES, PATTERN_METADATA,
            true);
  }

  static final List<String> exampleLogLines = List.of(
          "2024-12-23 19:21:26,925 [reactor-http-nio-2 b] DEBUG - ContrastNettyHttpDispatcherImpl.onResponseWritten(ContrastContext{http=HttpContext{HttpRequest@7f158250, null}, uri='/ping', assessment=AssessmentContext@3976bd9f{traceMap=TraceMap@5a09387d (with 26 items in it), jumpedContexts=true}}, io.netty.channel.CombinedChannelDuplexHandler$DelegatingChannelHandlerContext@729cde76, io.netty.handler.codec.http.DefaultFullHttpResponse@535af2b3) with channel NioSocketChannel@413c1e0e and pipeline DefaultChannelPipeline@49dc8fcb"
  );

  public static void main(String[] args) {
    testPatternMatching(exampleLogLines, PATTERN_METADATA.stream().filter(pmd -> pmd.patternId().startsWith("responseWritten")).toList(), true);
  }
}
