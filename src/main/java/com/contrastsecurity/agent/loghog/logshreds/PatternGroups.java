/* (C)2024 */
package com.contrastsecurity.agent.loghog.logshreds;

public class PatternGroups {

  public static final String TIMESTAMP_VAR = "timestamp";
  public static final String LOG_TIMESTAMP_XTRACT =
      "^(?<" + TIMESTAMP_VAR + ">\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2},\\d{3})";

  public static final String THREAD_VAR = "thread";
  public static final String LOGGER_VAR = "logger";
  public static final String LOG_THREAD_LOGGER_XTRACT =
      "\\[(?<" + THREAD_VAR + ">\\S+) (?<" + LOGGER_VAR + ">\\S+)]";

  public static final String SHORT_PREAMBLE_XTRACT =
      LOG_TIMESTAMP_XTRACT + " " + LOG_THREAD_LOGGER_XTRACT + " ";

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
  public static final String REQ_XTRACT = "request@(?<" + REQ_VAR + ">\\S+)";
  public static final String NO_REQ_XTRACT = "(?<" + REQ_VAR + ">~UNFOUND~)?";

  public static final String RESP_VAR = "resp";
  public static final String RESP_XTRACT = "response@(?<" + RESP_VAR + ">\\S+)";
  public static final String NO_RESP_XTRACT = "(?<" + RESP_VAR + ">~UNFOUND~)?";

  public static final String URL_VAR = "url";
  public static final String URL_XTRACT = "(?<" + URL_VAR + ">\\S+)";
  public static final String NO_URL_XTRACT = "(?<" + URL_VAR + ">~UNFOUND~)?";

  public static final String STACKFRAME_VAR = "stackframe";
  public static final String NO_STACKFRAME_XTRACT = "(?<" + STACKFRAME_VAR + ">~UNFOUND~)?";
}
