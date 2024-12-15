/* (C)2024 */
package com.contrastsecurity.agent.loghog.logshreds;

import org.jooq.impl.SQLDataType;

public class PatternGroups {

  public static final String VAL_ID_STR = "[^\\s@,}\\]\\)\\{:\"]+";
  public static final String VAL_ID_XTRACT_CLOSE = ">" + VAL_ID_STR + ")";

  public static final String ALLOW_AT_ID_STR = "[^\\s,}\\]\\)\\{:\"]+";
  public static final String ALLOW_AT_ID_XTRACT_CLOSE = ">" + ALLOW_AT_ID_STR + ")";

  public static final String NON_WS_XTRACT_CLOSE = ">\\S+)";

  public static final String XTRACT_OPEN = "(?<";
  public static final String UNFOUND_XTRACT_CLOSE = ">~UnFoUnD~)?";
  public static final String DECIMAL_XTRACT_CLOSE =   ">\\d+)";

  public static final String TIMESTAMP_VAR = "timestamp";
  public static final String TIMESTAMP_XTRACT =
          XTRACT_OPEN + TIMESTAMP_VAR + ">\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2},\\d{3})";
  public static final String NO_TIMESTAMP_XTRACT = UNFOUND(TIMESTAMP_VAR);

  public static final String THREAD_VAR = "thread";
  public static final String LOGGER_VAR = "logger";
  public static final String LOG_THREAD_LOGGER_XTRACT =
      "\\[(?<" + THREAD_VAR + ">[\\S ]+\\H) (?<" + LOGGER_VAR + ">\\S+)]";
  public static final String NO_THREAD_LOGGER_XTRACT =
      XTRACT_OPEN + THREAD_VAR + UNFOUND_XTRACT_CLOSE + XTRACT_OPEN + LOGGER_VAR + UNFOUND_XTRACT_CLOSE;

  public static final String SHORT_PREAMBLE_XTRACT =
      TIMESTAMP_XTRACT + " " + LOG_THREAD_LOGGER_XTRACT + " ";

  public static final String LOG_LEVEL_ERROR = "ERROR";
  public static final String LOG_LEVEL_WARN = "WARN";
  public static final String LOG_LEVEL_INFO = "INFO";
  public static final String LOG_LEVEL_DEBUG = "DEBUG";
  public static final String LOG_LEVEL_TRACE = "TRACE";

  public static final String LOG_LEVEL =
      "("
          + LOG_LEVEL_ERROR
          + "|"
          + LOG_LEVEL_WARN
          + "|"
          + LOG_LEVEL_INFO
          + "|"
          + LOG_LEVEL_DEBUG
          + "|"
          + LOG_LEVEL_TRACE
          + ")";

  public static final String LEVEL_VAR = "level";
  public static final String LOG_LEVEL_XTRACT = XTRACT_OPEN + LEVEL_VAR + ">" + LOG_LEVEL + ")";

  public static final String FULL_PREAMBLE_XTRACT = SHORT_PREAMBLE_XTRACT + LOG_LEVEL_XTRACT + " ";

  public static final String ERROR_PREAMBLE_XTRACT = SHORT_PREAMBLE_XTRACT + LOG_LEVEL_ERROR + " ";

  public static final String WARN_PREAMBLE_XTRACT = SHORT_PREAMBLE_XTRACT + LOG_LEVEL_WARN + " ";

  public static final String INFO_PREAMBLE_XTRACT = SHORT_PREAMBLE_XTRACT + LOG_LEVEL_INFO + " ";

  public static final String DEBUG_PREAMBLE_XTRACT = SHORT_PREAMBLE_XTRACT + LOG_LEVEL_DEBUG + " ";

  public static final String TRACE_PREAMBLE_XTRACT = SHORT_PREAMBLE_XTRACT + LOG_LEVEL_TRACE + " ";

  public static final String REQ_VAR = "req";
  public static final String REQ_XTRACT = "([^@\\s]+@)?(?<" + REQ_VAR + VAL_ID_XTRACT_CLOSE;
  public static final String NO_REQ_XTRACT = UNFOUND(REQ_VAR);

  public static final String RESP_VAR = "resp";
  public static final String RESP_XTRACT = "([^@\\s]+@)?(?<" + RESP_VAR +VAL_ID_XTRACT_CLOSE;
  public static final String NO_RESP_XTRACT = UNFOUND(RESP_VAR);

  public static final String URL_VAR = "url";
  public static final String URL_XTRACT = XTRACT_OPEN + URL_VAR + ">[^\\s']+)";
  public static final String NO_URL_XTRACT = UNFOUND(URL_VAR);

  public static final String STACKFRAME_VAR = "stackframe";
  public static final String NO_STACKFRAME_XTRACT = UNFOUND(STACKFRAME_VAR);

  public static final String TRACE_MAP_VAR = "traceMap";
  public static final String TRACE_MAP_XTRACT = "([^@\\s]+@)?(?<" + TRACE_MAP_VAR + NON_WS_XTRACT_CLOSE;
  public static final String NO_TRACE_MAP_XTRACT = UNFOUND(TRACE_MAP_VAR);

  public static final String TRACKED_OBJ_VAR = "trackedObj";
  public static final String TRACKED_OBJ_XTRACT = XTRACT_OPEN + TRACKED_OBJ_VAR + NON_WS_XTRACT_CLOSE;

  public static final String TRACE_NUM_VAR = "traceNum";
  public static final String TRACE_NUM_XTRACT = XTRACT_OPEN + TRACE_NUM_VAR + DECIMAL_XTRACT_CLOSE;

  public static final String TRACE_MAP_SIZE_VAR = "traceMapSize";
  public static final String TRACE_MAP_SIZE_XTRACT = XTRACT_OPEN + TRACE_MAP_SIZE_VAR + DECIMAL_XTRACT_CLOSE;
  public static final String NO_TRACE_MAP_SIZE_XTRACT = UNFOUND(TRACE_MAP_SIZE_VAR);

  public static final String CONCUR_CTX_VAR = "concurCtx";
  public static final String CONCUR_CTX_XTRACT = "[^@\\s]+@(?<" + CONCUR_CTX_VAR + VAL_ID_XTRACT_CLOSE;
  public static final String NO_CONCUR_CTX_XTRACT = UNFOUND(CONCUR_CTX_VAR);

  public static final String ASSESS_CTX_VAR = "assessCtx";
  public static final String ASSESS_CTX_XTRACT = "(AssessmentContext@)?(?<" + ASSESS_CTX_VAR + ALLOW_AT_ID_XTRACT_CLOSE;
  public static final String NO_ASSESS_CTX_XTRACT = UNFOUND(ASSESS_CTX_VAR);

  public static final String APP_CTX_VAR = "appCtx";
  public static final String APP_CTX_XTRACT = XTRACT_OPEN + APP_CTX_VAR + ALLOW_AT_ID_XTRACT_CLOSE;
  public static final String NO_APP_CTX_XTRACT = UNFOUND(APP_CTX_VAR);

  public static final String TASK_CLASS_VAR = "taskClass";
  public static final String TASK_CLASS_XTRACT = XTRACT_OPEN + TASK_CLASS_VAR + NON_WS_XTRACT_CLOSE;
  public static final String NO_TASK_CLASS_XTRACT = UNFOUND(TASK_CLASS_VAR);

  public static final String TASK_OBJ_VAR = "taskObj";
  public static final String TASK_OBJ_XTRACT = XTRACT_OPEN + TASK_OBJ_VAR + ALLOW_AT_ID_XTRACT_CLOSE;
  public static final String NO_TASK_OBJ_XTRACT = UNFOUND(TASK_OBJ_VAR);

  public static final String WRAP_INIT_VAR = "wrapInit";
  public static final String WRAP_INIT_XTRACT = XTRACT_OPEN + WRAP_INIT_VAR + NON_WS_XTRACT_CLOSE;
  public static final String NO_WRAP_INIT_XTRACT = UNFOUND(WRAP_INIT_VAR);

  public static final String WRAPPED_RUNNABLE_VAR = "wrappedRunnable";
  public static final String WRAPPED_RUNNABLE_XTRACT = XTRACT_OPEN + WRAPPED_RUNNABLE_VAR + NON_WS_XTRACT_CLOSE;
  public static final String NO_WRAPPED_RUNNABLE_XTRACT = UNFOUND(WRAPPED_RUNNABLE_VAR);

  public static final String FROM_THREAD_VAR = "fromThread";
  public static final String FROM_THREAD_XTRACT = XTRACT_OPEN + FROM_THREAD_VAR + NON_WS_XTRACT_CLOSE;
  public static final String NO_FROM_THREAD_XTRACT = UNFOUND(FROM_THREAD_VAR);

  public static final String NATIVE_RESP_VAR = "nativeResp";
  public static final String NATIVE_RESP_XTRACT = XTRACT_OPEN + NATIVE_RESP_VAR + NON_WS_XTRACT_CLOSE;
  public static final String NO_NATIVE_RESP_XTRACT = UNFOUND(NATIVE_RESP_VAR);

  public static final String OUTPUT_MECHANISM_VAR = "outputMechanism";
  public static final String OUTPUT_MECHANISM_XTRACT = XTRACT_OPEN + OUTPUT_MECHANISM_VAR + NON_WS_XTRACT_CLOSE;
  public static final String NO_OUTPUT_MECHANISM_XTRACT = UNFOUND(OUTPUT_MECHANISM_VAR);

  public static final String JUMPED_ASSESS_CTX_VAR = "jumpedAssessCtx";
  public static final String JUMPED_ASSESS_CTX_XTRACT = XTRACT_OPEN + JUMPED_ASSESS_CTX_VAR + VAL_ID_XTRACT_CLOSE;
  public static final String NO_JUMPED_ASSESS_CTX_XTRACT = UNFOUND(JUMPED_ASSESS_CTX_VAR);

  public static final String CHANNEL_HANDLER_CTX_VAR = "channelHandlerCtx";
  public static final String CHANNEL_HANDLER_CTX_XTRACT = XTRACT_OPEN + CHANNEL_HANDLER_CTX_VAR + ALLOW_AT_ID_XTRACT_CLOSE;
  public static final String NO_CHANNEL_HANDLER_CTX_XTRACT = UNFOUND(CHANNEL_HANDLER_CTX_VAR);

  public static final String CHANNEL_VAR = "channel";
  public static final String CHANNEL_XTRACT = XTRACT_OPEN + CHANNEL_VAR + ALLOW_AT_ID_XTRACT_CLOSE;
  public static final String NO_CHANNEL_XTRACT = UNFOUND(CHANNEL_VAR);

  public static final String PIPELINE_VAR = "pipeline";
  public static final String PIPELINE_XTRACT = XTRACT_OPEN + PIPELINE_VAR + ALLOW_AT_ID_XTRACT_CLOSE;
  public static final String NO_PIPELINE_XTRACT = UNFOUND(PIPELINE_VAR);

  public static final String NETTY_HTTP_MSG_VAR = "nettyHttpMsg";
  public static final String NETTY_HTTP_MSG_XTRACT = XTRACT_OPEN + NETTY_HTTP_MSG_VAR + ALLOW_AT_ID_XTRACT_CLOSE;
  public static final String NO_NETTY_HTTP_MSG_XTRACT = UNFOUND(NETTY_HTTP_MSG_VAR);

  public static final String DECODER_STATE_VAR = "decoderState";
  public static final String DECODER_STATE_XTRACT = XTRACT_OPEN + DECODER_STATE_VAR + ALLOW_AT_ID_XTRACT_CLOSE;
  public static final String NO_DECODER_STATE_XTRACT = UNFOUND(DECODER_STATE_VAR);

public static final String RULE_VAR = "rule";
  public static final String RULE_XTRACT = XTRACT_OPEN + RULE_VAR + VAL_ID_XTRACT_CLOSE;
  public static final String NO_RULE_XTRACT = UNFOUND(RULE_VAR);

public static final String TRACE_VAR = "trace";
  public static final String TRACE_XTRACT = XTRACT_OPEN + TRACE_VAR + VAL_ID_XTRACT_CLOSE;
  public static final String NO_TRACE_XTRACT = UNFOUND(TRACE_VAR);

public static final String FATE_VAR = "fate";
  public static final String FATE_XTRACT = XTRACT_OPEN + FATE_VAR + VAL_ID_XTRACT_CLOSE;
  public static final String NO_FATE_XTRACT = UNFOUND(FATE_VAR);

public static final String TRACE_HASH_VAR = "traceHash";
  public static final String TRACE_HASH_XTRACT = XTRACT_OPEN + TRACE_HASH_VAR + VAL_ID_XTRACT_CLOSE;
  public static final String NO_TRACE_HASH_XTRACT = UNFOUND(TRACE_HASH_VAR);

public static final String RPT_QUEUE_VAR = "rptQueue";
  public static final String RPT_QUEUE_XTRACT = XTRACT_OPEN + RPT_QUEUE_VAR + ALLOW_AT_ID_XTRACT_CLOSE;
  public static final String NO_RPT_QUEUE_XTRACT = UNFOUND(RPT_QUEUE_VAR);

  private static String UNFOUND(final String groupName) {
    return nullCaptureGroupPattern(groupName);
  }

  public static String nullCaptureGroupPattern(final String groupName) {
    return XTRACT_OPEN + groupName + UNFOUND_XTRACT_CLOSE;
  }
}
