/* (C)2024 */
package com.contrastsecurity.agent.loghog.logshreds;

public class PatternGroups {

  public static final String VAL_ID_STR = "[^\\s@,}\\]]+";
  public static final String VAL_ID_XTRACT_CLOSE = ">" + VAL_ID_STR + ")";

  public static final String ALLOW_AT_ID_STR = "[^\\s,}\\]]+";
  public static final String ALLOW_AT_ID_XTRACT_CLOSE = ">" + ALLOW_AT_ID_STR + ")";

  public static final String NON_WS_XTRACT_CLOSE = ">\\S+)";

  public static final String UNFOUND_XTRACT_CLOSE = ">~UNFOUND~)?";
  public static final String DECIMAL_XTRACT_CLOSE =   ">\\d+)";

  public static final String TIMESTAMP_VAR = "timestamp";
  public static final String TIMESTAMP_XTRACT =
      "^(?<" + TIMESTAMP_VAR + ">\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2},\\d{3})";
  public static final String NO_TIMESTAMP_XTRACT = "(?<" + TIMESTAMP_VAR + UNFOUND_XTRACT_CLOSE;

  public static final String THREAD_VAR = "thread";
  public static final String LOGGER_VAR = "logger";
  public static final String LOG_THREAD_LOGGER_XTRACT =
      "\\[(?<" + THREAD_VAR + ">[\\S ]+\\H) (?<" + LOGGER_VAR + ">\\S+)]";
  public static final String NO_THREAD_LOGGER_XTRACT =
      "(?<" + THREAD_VAR + ">~UNFOUND~)?(?<" + LOGGER_VAR + UNFOUND_XTRACT_CLOSE;

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
  public static final String LOG_LEVEL_XTRACT = "(?<" + LEVEL_VAR + ">" + LOG_LEVEL + ")";

  public static final String FULL_PREAMBLE_XTRACT = SHORT_PREAMBLE_XTRACT + LOG_LEVEL_XTRACT + " ";

  public static final String ERROR_PREAMBLE_XTRACT = SHORT_PREAMBLE_XTRACT + LOG_LEVEL_ERROR + " ";

  public static final String WARN_PREAMBLE_XTRACT = SHORT_PREAMBLE_XTRACT + LOG_LEVEL_WARN + " ";

  public static final String INFO_PREAMBLE_XTRACT = SHORT_PREAMBLE_XTRACT + LOG_LEVEL_INFO + " ";

  public static final String DEBUG_PREAMBLE_XTRACT = SHORT_PREAMBLE_XTRACT + LOG_LEVEL_DEBUG + " ";

  public static final String TRACE_PREAMBLE_XTRACT = SHORT_PREAMBLE_XTRACT + LOG_LEVEL_TRACE + " ";

  public static final String REQ_VAR = "req";
  public static final String REQ_XTRACT = "[^@\\s]+@(?<" + REQ_VAR + VAL_ID_XTRACT_CLOSE;
  public static final String NO_REQ_XTRACT = "(?<" + REQ_VAR + UNFOUND_XTRACT_CLOSE;

  public static final String RESP_VAR = "resp";
  public static final String RESP_XTRACT = "[^@\\s]+@(?<" + RESP_VAR +VAL_ID_XTRACT_CLOSE;
  public static final String NO_RESP_XTRACT = "(?<" + RESP_VAR + UNFOUND_XTRACT_CLOSE;

  public static final String URL_VAR = "url";
  public static final String URL_XTRACT = "(?<" + URL_VAR + NON_WS_XTRACT_CLOSE;
  public static final String NO_URL_XTRACT = "(?<" + URL_VAR + UNFOUND_XTRACT_CLOSE;

  public static final String STACKFRAME_VAR = "stackframe";
  public static final String NO_STACKFRAME_XTRACT = "(?<" + STACKFRAME_VAR + UNFOUND_XTRACT_CLOSE;

  public static final String TRACE_MAP_VAR = "traceMap";
  public static final String TRACE_MAP_XTRACT = "([^@\\s]+@)?(?<" + TRACE_MAP_VAR + NON_WS_XTRACT_CLOSE;
  public static final String NO_TRACE_MAP_XTRACT = "(?<" + TRACE_MAP_VAR + UNFOUND_XTRACT_CLOSE;

  public static final String TRACKED_OBJ_VAR = "trackedObj";
  public static final String TRACKED_OBJ_XTRACT = "(?<" + TRACKED_OBJ_VAR + NON_WS_XTRACT_CLOSE;

  public static final String TRACE_NUM_VAR = "traceNum";
  public static final String TRACE_NUM_XTRACT = "(?<" + TRACE_NUM_VAR + DECIMAL_XTRACT_CLOSE;

  public static final String TRACE_MAP_SIZE_VAR = "traceMapSize";
  public static final String TRACE_MAP_SIZE_XTRACT = "(?<" + TRACE_MAP_SIZE_VAR + DECIMAL_XTRACT_CLOSE;

  public static final String CONCUR_CTX_VAR = "concurCtx";
  public static final String CONCUR_CTX_XTRACT = "[^@\\s]+@(?<" + CONCUR_CTX_VAR + VAL_ID_XTRACT_CLOSE;
  public static final String NO_CONCUR_CTX_XTRACT = "(?<" + CONCUR_CTX_VAR + UNFOUND_XTRACT_CLOSE;

  public static final String ASSESS_CTX_VAR = "assessCtx";
  public static final String ASSESS_CTX_XTRACT = "(?<" + ASSESS_CTX_VAR + VAL_ID_XTRACT_CLOSE;
  public static final String NO_ASSESS_CTX_XTRACT = "(?<" + ASSESS_CTX_VAR + UNFOUND_XTRACT_CLOSE;

  public static final String APP_CTX_VAR = "appCtx";
  public static final String APP_CTX_XTRACT = "(?<" + APP_CTX_VAR + ALLOW_AT_ID_XTRACT_CLOSE;
  public static final String NO_APP_CTX_XTRACT = "(?<" + APP_CTX_VAR + UNFOUND_XTRACT_CLOSE;

  public static final String TASK_CLASS_VAR = "taskClass";
  public static final String TASK_CLASS_XTRACT = "(?<" + TASK_CLASS_VAR + NON_WS_XTRACT_CLOSE;
  public static final String NO_TASK_CLASS_XTRACT = "(?<" + TASK_CLASS_VAR + UNFOUND_XTRACT_CLOSE;

  public static final String TASK_OBJ_VAR = "taskObj";
  public static final String TASK_OBJ_XTRACT = "(?<" + TASK_OBJ_VAR + NON_WS_XTRACT_CLOSE;
  public static final String NO_TASK_OBJ_XTRACT = "(?<" + TASK_OBJ_VAR + UNFOUND_XTRACT_CLOSE;

  public static final String WRAP_INIT_VAR = "wrapInit";
  public static final String WRAP_INIT_XTRACT = "(?<" + WRAP_INIT_VAR + NON_WS_XTRACT_CLOSE;
  public static final String NO_WRAP_INIT_XTRACT = "(?<" + WRAP_INIT_VAR + UNFOUND_XTRACT_CLOSE;

  public static final String WRAPPED_RUNNABLE_VAR = "wrappedRunnable";
  public static final String WRAPPED_RUNNABLE_XTRACT = "(?<" + WRAPPED_RUNNABLE_VAR + NON_WS_XTRACT_CLOSE;
  public static final String NO_WRAPPED_RUNNABLE_XTRACT = "(?<" + WRAPPED_RUNNABLE_VAR + UNFOUND_XTRACT_CLOSE;

  public static final String FROM_THREAD_VAR = "fromThread";
  public static final String FROM_THREAD_XTRACT = "(?<" + FROM_THREAD_VAR + NON_WS_XTRACT_CLOSE;
  public static final String NO_FROM_THREAD_XTRACT = "(?<" + FROM_THREAD_VAR + UNFOUND_XTRACT_CLOSE;

  public static final String NATIVE_RESP_VAR = "nativeResp";
  public static final String NATIVE_RESP_XTRACT = "(?<" + NATIVE_RESP_VAR + NON_WS_XTRACT_CLOSE;
  public static final String NO_NATIVE_RESP_XTRACT = "(?<" + NATIVE_RESP_VAR + UNFOUND_XTRACT_CLOSE;

  public static final String OUTPUT_MECHANISM_VAR = "outputMechanism";
  public static final String OUTPUT_MECHANISM_XTRACT = "(?<" + OUTPUT_MECHANISM_VAR + NON_WS_XTRACT_CLOSE;
  public static final String NO_OUTPUT_MECHANISM_XTRACT = "(?<" + OUTPUT_MECHANISM_VAR + UNFOUND_XTRACT_CLOSE;


}
