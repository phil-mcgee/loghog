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
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.ASSESS_CTX_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.ASSESS_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.CHANNEL_HANDLER_CTX_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.CHANNEL_HANDLER_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.CHANNEL_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.CHANNEL_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.DEBUG_PREAMBLE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.DECODER_STATE_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.DECODER_STATE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.FATE_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.FATE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.INFO_PREAMBLE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.JUMPED_ASSESS_CTX_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.JUMPED_ASSESS_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NETTY_HTTP_MSG_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NETTY_HTTP_MSG_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_APP_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_CHANNEL_HANDLER_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_CHANNEL_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_CONCUR_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_DECODER_STATE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_FATE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_JUMPED_ASSESS_CTX_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_NETTY_HTTP_MSG_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_RPT_QUEUE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_RULE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_TASK_CLASS_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_TASK_OBJ_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_TRACE_HASH_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_TRACE_MAP_SIZE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_TRACE_MAP_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_TRACE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_URL_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_WRAPPED_RUNNABLE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_WRAP_INIT_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.REQ_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.REQ_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.RESP_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.RESP_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.RPT_QUEUE_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.RPT_QUEUE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.RULE_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.RULE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TASK_CLASS_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TASK_OBJ_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TASK_OBJ_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.THREAD_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TIMESTAMP_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TRACE_HASH_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TRACE_HASH_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TRACE_MAP_SIZE_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TRACE_MAP_SIZE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TRACE_MAP_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TRACE_MAP_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TRACE_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TRACE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.URL_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.URL_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.WRAPPED_RUNNABLE_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.WRAPPED_RUNNABLE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.WRAP_INIT_VAR;

public class VulnShred extends BaseShred {

  static final String SHRED_TABLE_NAME = "VULN";
  static final String SHRED_KEY_COLUMN = "LINE";

  static final List<ShredRowMetaData> SHRED_METADATA =
      List.of(
          new ShredRowMetaData("LINE", SQLDataType.INTEGER.notNull(), Integer.class, LOG_TABLE_LINE_COL),
          new ShredRowMetaData("TIMESTAMP", SQLDataType.LOCALDATETIME(3), LocalDateTime.class, TIMESTAMP_VAR),
          new ShredRowMetaData("THREAD", SQLDataType.VARCHAR, String.class, THREAD_VAR),
          new ShredRowMetaData("PATTERN", SQLDataType.VARCHAR.notNull(), String.class, SHRED_TABLE_PATTERN_COL),
          new ShredRowMetaData("URL", SQLDataType.VARCHAR, String.class, URL_VAR),
          new ShredRowMetaData("RULE", SQLDataType.VARCHAR, String.class, RULE_VAR),
          new ShredRowMetaData("TRACE", SQLDataType.INTEGER, Integer.class, TRACE_VAR),
          new ShredRowMetaData("FATE", SQLDataType.VARCHAR, String.class, FATE_VAR),
          new ShredRowMetaData("TRACE_HASH", SQLDataType.VARCHAR, String.class, TRACE_HASH_VAR),
          new ShredRowMetaData("RPT_QUEUE", SQLDataType.VARCHAR, String.class, RPT_QUEUE_VAR)
      );

  static final String MISFITS_TABLE_NAME = "VULN_MISFITS";
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
    "- !LM!TraceFate|",
    "- Added finding for rule ID:",
          " added to reporting queue:",
          "type=FINDING_DISCOVERED, ",
          "DataFlowTriggerHandlerImpl] DEBUG - TRACE  - URI:"
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

//  static final String ASSESS_NONNULL_XTRACTS = ASSESS_CTX_XTRACT + "\\{traceMap="
//          + TRACE_MAP_XTRACT + " \\(with " + TRACE_MAP_SIZE_XTRACT + " items in it\\), jumpedContexts=" + JUMPED_ASSESS_CTX_XTRACT + "\\}\\}";
//  static final String ASSESS_NULL_XTRACTS = ASSESS_CTX_XTRACT + "(\\{)?\\}";
//  static final String WITH_WRAPPED_RUNNABLE_XTRACT =  "\\) wrapping task " + WRAPPED_RUNNABLE_XTRACT+ " with ContrastContext";
//  static final String WITHOUT_WRAPPED_RUNNABLE_XTRACT =  "\\) with ContrastContext";
//  static final String START_CONTRAST_CONTEXT_EXTRACT = "ContrastContext\\{http=HttpContext\\{" + REQ_XTRACT + ", " + RESP_XTRACT + "\\}, uri='" + URL_XTRACT + "', assessment=";

//           NO_URL_XTRACT + NO_RULE_XTRACT + NO_TRACE_XTRACT + NO_FATE_XTRACT + NO_TRACE_HASH_XTRACT + NO_RPT_QUEUE_XTRACT


    static final List<PatternMetadata> PATTERN_METADATA =
      List.of(
              // 2024-11-20 15:38:40,995 [reactor-http-nio-2 Finding] DEBUG - !LM!TraceFate|NewFinding|ruleId=path-traversal
              new PatternMetadata(
                      "traceFate",
                      List.of("- !LM!TraceFate|"),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- !LM!TraceFate\\|"
                                              + FATE_XTRACT + "\\|ruleId=" + RULE_XTRACT
                                      + NO_URL_XTRACT + NO_TRACE_XTRACT + NO_TRACE_HASH_XTRACT + NO_RPT_QUEUE_XTRACT
                                      + "$")),
              // 2024-11-20 15:38:50,938 [reactor-http-nio-2 QueueFindingListener] INFO - Added finding for rule ID: path-traversal (hash=1142718516)
              new PatternMetadata(
                      "addedFinding",
                      List.of("- Added finding for rule ID:"),
                      Pattern.compile(
                              INFO_PREAMBLE_XTRACT
                          + "- Added finding for rule ID: "
                          + RULE_XTRACT + " \\(hash=" + TRACE_HASH_XTRACT + "\\)"
                          + NO_URL_XTRACT + NO_TRACE_XTRACT + NO_FATE_XTRACT  + NO_RPT_QUEUE_XTRACT
                          + "$")),
              // 2024-11-20 15:38:50,944 [reactor-http-nio-2 g] DEBUG - Trace 1142718516 added to reporting queue: Trace path-traversal: TRACE 884 (881)
              new PatternMetadata(
                      "toRptQueue",
                      List.of(" added to reporting queue:"),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- Trace " + TRACE_HASH_XTRACT
                                      + " added to reporting queue: "
                                      // TODO what is the second trace number?
                                      + "Trace " + RULE_XTRACT + ": TRACE " + TRACE_XTRACT + " \\(\\d+\\)"
                                      + NO_URL_XTRACT + NO_FATE_XTRACT + NO_RPT_QUEUE_XTRACT
                                      + "$")),
              // 2024-11-20 15:38:47,945 [reactor-http-nio-2 AMQP Publisher] DEBUG - MQPublisherImpl#publish call: exchangeName: , queueName: -00000-V5_1.it_tests_sources_V5, properties: #contentHeader<basic>(...)
              // , body: {"hash":3277375950,"version":4,"session_id":"AcceptanceTestSessionId","ruleId":"path-traversal",
               new PatternMetadata(
                      "mqpublish",
                      List.of("- MQPublisherImpl#publish call:", "type=FINDING_DISCOVERED," ),
                      Pattern.compile(
                                DEBUG_PREAMBLE_XTRACT
                                      + "- MQPublisherImpl#publish call: exchangeName:[^,]+, queueName: " + RPT_QUEUE_XTRACT
                                      + ", properties:[^\\(]+" + "\\([^\\)]+\\)"
                                      + ", body: \\{\"hash\":"
                                      + TRACE_HASH_XTRACT + ",\"version\":.+?,\"ruleId\":\""
                                      + RULE_XTRACT + "\","
                                      + ".+\"standardNormalizedUri\":\"(?<" + URL_VAR + ">[^\"]+)\",.+"
                                      + NO_TRACE_XTRACT + NO_FATE_XTRACT
                                      + "$")),
              // 2024-11-20 15:38:42,968 [reactor-http-nio-2 DataFlowTriggerHandlerImpl] DEBUG - TRACE  - URI: /sources/v5_0/serverWebExchange-formData - PLUG
              new PatternMetadata(
                      "trigger",
                      List.of("DataFlowTriggerHandlerImpl] DEBUG - TRACE  - URI:"),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- TRACE  - URI: "
                                      + URL_XTRACT
                                      + " - PLUG"
                                      + NO_RULE_XTRACT + NO_TRACE_XTRACT + NO_FATE_XTRACT + NO_TRACE_HASH_XTRACT + NO_RPT_QUEUE_XTRACT
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

  public VulnShred() {
    super(SHRED_METADATA, SHRED_SQL_TABLE, MISFITS_METADATA, MISFITS_SQL_TABLE, SHRED_SOURCE);
  }

  static final List<String> exampleLogLines = List.of(
//    "2024-11-20 15:38:40,995 [reactor-http-nio-2 Finding] DEBUG - !LM!TraceFate|NewFinding|ruleId=path-traversal",
//    "2024-11-20 15:38:50,938 [reactor-http-nio-2 QueueFindingListener] INFO - Added finding for rule ID: path-traversal (hash=1142718516)",
//    "2024-11-20 15:38:50,944 [reactor-http-nio-2 g] DEBUG - Trace 1142718516 added to reporting queue: Trace path-traversal: TRACE 884 (881)",
//    new StringBuilder("2024-11-20 15:38:47,945 [reactor-http-nio-2 AMQP Publisher] DEBUG - MQPublisherImpl#publish call: exchangeName: , queueName: -00000-V5_1.it_tests_sources_V5, properties: #contentHeader<basic>(content-type=null, content-encoding=null, headers=null, delivery-mode=null, priority=null, correlation-id=null, reply-to=null, expiration=null, message-id=null, timestamp=null, type=FINDING_DISCOVERED, user-id=null, app-id=null, cluster-id=null), ")
//      .append("body: {\"hash\":3277375950,\"version\":4,\"session_id\":\"AcceptanceTestSessionId\",\"ruleId\":\"path-traversal\",\"properties\":{\"entrypointType\":\"HTTP\",\"entrypointSignature\":\"com.contrastsecurity.testapp.v5.PolicyController$SourceEndpoints.serverHttpRequestQueryParams(org.springframework.http.server.reactive.ServerHttpRequest)\"},")
//      .append("...")
//      .append(",\"observations\":[{\"url\":\"/sources/v5_0/serverHttpRequest-queryParams\",\"type\":\"HTTP\",\"verb\":\"POST\"}]}],\"request\":{\"contextPath\":\"/\",\"headers\":{\"Accept-Encoding\":[\"gzip\"],\"Connection\":[\"Keep-Alive\"],\"Content-Length\":[\"11\"],\"Content-Type\":[\"plain/text; charset\\u003dutf-8\"],\"contrast-mq-name\":[\"-00000-V5_1.it_tests_sources_V5\"],\"cookie\":[\"cookie\\u003dcookieVal\"],\"header\":[\"headerVal\"],\"Host\":[\"localhost:33766\"],\"User-Agent\":[\"okhttp/4.9.1\"]},\"method\":\"POST\",\"standardNormalizedUri\":\"/sources/v5_0/serverHttpRequest-queryParams\",\"parameters\":{\"requestParam\":[\"foo\"]},\"port\":8080,\"protocol\":\"http\",\"queryString\":\"requestParam\\u003dfoo\",\"uri\":\"/sources/v5_0/serverHttpRequest-queryParams\",\"version\":\"1.1\"}}")
//      .toString(),
      "2024-11-20 15:38:42,968 [reactor-http-nio-2 DataFlowTriggerHandlerImpl] DEBUG - TRACE  - URI: /sources/v5_0/serverWebExchange-formData - PLUG"
  );
  
  public static void main(String[] args) {
    testPatternMatching(exampleLogLines, PATTERN_METADATA, true);
  }
}
