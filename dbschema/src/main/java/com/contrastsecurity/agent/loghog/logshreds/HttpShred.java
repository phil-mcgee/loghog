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
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.DEBUG_PREAMBLE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NATIVE_RESP_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NATIVE_RESP_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_NATIVE_RESP_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_OUTPUT_MECHANISM_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_REQ_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_RESP_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_URL_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.OUTPUT_MECHANISM_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.OUTPUT_MECHANISM_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.REQ_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.REQ_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.RESP_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.RESP_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.THREAD_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TIMESTAMP_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.URL_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.URL_XTRACT;

public class HttpShred extends BaseShred {

  static final String SHRED_TABLE_NAME = "HTTP";
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
                  new ShredRowMetaData("THREAD", SQLDataType.VARCHAR, String.class, THREAD_VAR),
                  new ShredRowMetaData(
                          "PATTERN", SQLDataType.VARCHAR.notNull(), String.class, SHRED_TABLE_PATTERN_COL),
                  new ShredRowMetaData("REQ", SQLDataType.VARCHAR, String.class, REQ_VAR),
                  new ShredRowMetaData("RESP", SQLDataType.VARCHAR, String.class, RESP_VAR),
                  new ShredRowMetaData("URL", SQLDataType.VARCHAR, String.class, URL_VAR),
                  new ShredRowMetaData("NATIVE_RESP", SQLDataType.VARCHAR, String.class, NATIVE_RESP_VAR),
                  new ShredRowMetaData("OUTPUT_MECHANISM", SQLDataType.VARCHAR, String.class, OUTPUT_MECHANISM_VAR));

  static final String MISFITS_TABLE_NAME = "HTTP_MISFITS";
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
                          jooq()
                                  .createIndex("IDX_" + SHRED_TABLE_NAME + "_" + "REQ")
                                  .on(SHRED_TABLE_NAME, "REQ")
                                  .getSQL(),
                          jooq()
                                  .createIndex("IDX_" + SHRED_TABLE_NAME + "_" + "REQ" + "_" + "PATTERN")
                                  .on(SHRED_TABLE_NAME, "REQ", "PATTERN")
                                  .getSQL()));

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
          " HttpManager] "
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

  static final String HTTP_MANAGER_PREAMBLE_XTRACT = DEBUG_PREAMBLE_XTRACT + "- HttpContext\\{" + REQ_XTRACT + ", " + RESP_XTRACT + "\\} ";
  static final List<PatternMetadata> PATTERN_METADATA =
          List.of(
                  //!LM!RequestTime|RequestEnded|uri=/routecoverage/annotation/&elapsed=29
                  new PatternMetadata(
                          "lmReqTime",
                          List.of("!LM!RequestTime|RequestEnded"),
                          Pattern.compile(
                                  DEBUG_PREAMBLE_XTRACT
                                          + "- !LM!RequestTime\\|RequestEnded\\|uri="
                                          + "(?<" + URL_VAR + ">[^&]+)"
                                          + "&elapsed=\\d+"
                                          + "$")),
                  //Capturing response to memory
                  new PatternMetadata(
                          "respCapture",
                          List.of("Capturing response to memory"),
                          Pattern.compile(HTTP_MANAGER_PREAMBLE_XTRACT + "- onResponseStart\\(\\) Capturing response to memory"
                                  + "$")),
                  //2024-11-07 18:04:50,774 [reactor-http-nio-4 HttpManager] DEBUG - Request ending for /auto-binding/v1_0/autobind-unsafe - response is k@2a7ec4a7 and output mechanism is null
                  // FIXME OUTPUT_MECHANISM reports the string null instead of a null value
                  new PatternMetadata(
                          "reqEnding",
                          List.of(" Request ending for "),
                          Pattern.compile(HTTP_MANAGER_PREAMBLE_XTRACT + "- onRequestEnd\\(\\) Request ending for " + URL_XTRACT + " - response is "
                                  + NATIVE_RESP_XTRACT + " and output mechanism is " + OUTPUT_MECHANISM_XTRACT
                                  + "$")),
                  //Response was empty for URI /sources/v5_0/matrixVariable/foo;var=strawberries
                  new PatternMetadata(
                          "respEmpty",
                          List.of("Response was empty for "),
                          Pattern.compile(HTTP_MANAGER_PREAMBLE_XTRACT + "- analyzeResponseContents\\(\\) Response was empty for URI " + URL_XTRACT +
                                  "$")),
                  //Response was empty for URI /sources/v5_0/matrixVariable/foo;var=strawberries
                  new PatternMetadata(
                          "nullReqRespStart",
                          List.of("Current HTTPRequest was null"),
                          Pattern.compile(HTTP_MANAGER_PREAMBLE_XTRACT + "- onResponseStart\\(\\) Current HTTPRequest was null" +
                                   "$")),
                  //Response was empty for URI /sources/v5_0/matrixVariable/foo;var=strawberries
                  new PatternMetadata(
                          "nullRespCrumb",
                          List.of("- logCrumbData() Unexpected null response for request"),
                          Pattern.compile(HTTP_MANAGER_PREAMBLE_XTRACT + "- logCrumbData\\(\\) Unexpected null response for request.+"
                                  + "$"))
//                  "2024-12-14 19:42:24,815 [reactor-http-nio-3 HttpManager] DEBUG - HttpContext{HttpRequest@7d722350, null} - logCrumbData() Unexpected null response for request=[HttpRequest{protocol=http, version=HTTP/1.1, method='GET', uri='/routecoverage/annotation/get', queryString='param=paramFromQuery&param2=param2FromQuery&name=%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E', normalizedUri='/routecoverage/annotation/get', port=8080, parameters={name=[Ljava.lang.String;@7d1fba1b, param=[Ljava.lang.String;@78283f1a, param2=[Ljava.lang.String;@5204212a}, headers={Accept-Encoding=[Ljava.lang.String;@29349f0b, Connection=[Ljava.lang.String;@24f1c64d, contrast-mq-name=[Ljava.lang.String;@786ed221, Host=[Ljava.lang.String;@407cd952, User-Agent=[Ljava.lang.String;@5f509696, x-contrast-1=[Ljava.lang.String;@64b5ee60, x-contrast-2=[Ljava.lang.String;@55f38f7a}, contextPath='/', serverVersionInfo='null', cachedBodyStr='null', contentLength=0, cachedContentType=com.contrastsecurity.agent.http.ContrastContentType@65524393, requestID=2104632144, template='/routecoverage/annotation/get', normalizedTemplate='/routecoverage/annotation/get', path='/routecoverage/annotation/get', secure=false, type=NETTY, active=false, capturingInMemory=false}], CRUMB:"
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

  public HttpShred() {
    super(SHRED_METADATA, SHRED_SQL_TABLE, MISFITS_METADATA, MISFITS_SQL_TABLE, SHRED_SOURCE, true);
  }

  static final List<String> exampleLogLines = List.of(
//  "2024-12-13 15:09:58,700 [reactor-http-nio-1 HttpManager] DEBUG - HttpContext{HttpRequest@57fbf777, m@1fac8f85} - onResponseStart() Capturing response to memory"
//          "2024-12-13 15:09:51,517 [reactor-http-nio-2 HttpManager] DEBUG - HttpContext{HttpRequest@0a4277f9, m@5b4aefa7} - onRequestEnd() Request ending for /ping - response is m@5b4aefa7 and output mechanism is null"
//          "2024-12-13 15:09:52,115 [reactor-http-nio-3 HttpManager] DEBUG - HttpContext{HttpRequest@6a40d6a3, m@1a309d43} - analyzeResponseContents() Response was empty for URI /sources/v5_0/serverHttpRequest-body"
//          "2024-12-13 15:09:51,750 [reactor-http-nio-2 HttpManager] DEBUG - HttpContext{null, null} - onResponseStart() Current HTTPRequest was null"
          "2024-12-14 19:42:24,815 [reactor-http-nio-3 HttpManager] DEBUG - HttpContext{HttpRequest@7d722350, null} - logCrumbData() Unexpected null response for request=[HttpRequest{protocol=http, version=HTTP/1.1, method='GET', uri='/routecoverage/annotation/get', queryString='param=paramFromQuery&param2=param2FromQuery&name=%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E', normalizedUri='/routecoverage/annotation/get', port=8080, parameters={name=[Ljava.lang.String;@7d1fba1b, param=[Ljava.lang.String;@78283f1a, param2=[Ljava.lang.String;@5204212a}, headers={Accept-Encoding=[Ljava.lang.String;@29349f0b, Connection=[Ljava.lang.String;@24f1c64d, contrast-mq-name=[Ljava.lang.String;@786ed221, Host=[Ljava.lang.String;@407cd952, User-Agent=[Ljava.lang.String;@5f509696, x-contrast-1=[Ljava.lang.String;@64b5ee60, x-contrast-2=[Ljava.lang.String;@55f38f7a}, contextPath='/', serverVersionInfo='null', cachedBodyStr='null', contentLength=0, cachedContentType=com.contrastsecurity.agent.http.ContrastContentType@65524393, requestID=2104632144, template='/routecoverage/annotation/get', normalizedTemplate='/routecoverage/annotation/get', path='/routecoverage/annotation/get', secure=false, type=NETTY, active=false, capturingInMemory=false}], CRUMB:"
  );


  public static void main(String[] args) {
    testPatternMatching(exampleLogLines, PATTERN_METADATA.stream().filter(pmd -> pmd.patternId().startsWith("")).toList(), true);
  }
}