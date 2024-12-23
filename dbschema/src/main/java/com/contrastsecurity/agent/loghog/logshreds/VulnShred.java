/* (C)2024 */
package com.contrastsecurity.agent.loghog.logshreds;

import com.contrastsecurity.agent.loghog.shred.impl.BaseShredSource;
import com.contrastsecurity.agent.loghog.shred.impl.BaseShred;
import com.contrastsecurity.agent.loghog.shred.PatternMetadata;
import com.contrastsecurity.agent.loghog.shred.impl.PatternRowValuesExtractor;
import com.contrastsecurity.agent.loghog.shred.PatternSignatures;
import com.contrastsecurity.agent.loghog.shred.RowClassifier;
import com.contrastsecurity.agent.loghog.shred.RowValuesExtractor;
import com.contrastsecurity.agent.loghog.shred.ShredRowMetaData;
import com.contrastsecurity.agent.loghog.shred.impl.ShredSqlTable;
import com.contrastsecurity.agent.loghog.shred.impl.TextSignatureRowClassifier;
import com.contrastsecurity.agent.loghog.shred.pmd.PmdShred;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static com.contrastsecurity.agent.loghog.db.EmbeddedDatabaseFactory.jooq;
import static com.contrastsecurity.agent.loghog.db.LogTable.LOG_TABLE_NAME;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.DEBUG_PREAMBLE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.FATE_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.FATE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.INFO_PREAMBLE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.RPT_QUEUE_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.RPT_QUEUE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.RULE_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.RULE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.THREAD_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TIMESTAMP_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TRACE_HASH_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TRACE_HASH_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TRACE_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TRACE_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.URL_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.URL_XTRACT;

public class VulnShred extends PmdShred {

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

  public static final Set<String> ENTRY_SIGNATURES = Set.of("- !LM!TraceFate|",
    "- Added finding for rule ID:",
          " added to reporting queue: Trace",
          "type=FINDING_DISCOVERED, ",
          "DataFlowTriggerHandlerImpl] DEBUG - TRACE  - URI:"
  );

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
                                      + "$")),
              // 2024-11-20 15:38:50,938 [reactor-http-nio-2 QueueFindingListener] INFO - Added finding for rule ID: path-traversal (hash=1142718516)
              new PatternMetadata(
                      "addedFinding",
                      List.of("- Added finding for rule ID:"),
                      Pattern.compile(
                              INFO_PREAMBLE_XTRACT
                          + "- Added finding for rule ID: "
                          + RULE_XTRACT + " \\(hash=" + TRACE_HASH_XTRACT + "\\)"
                          + "$")),
              // 2024-11-20 15:38:50,944 [reactor-http-nio-2 g] DEBUG - Trace 1142718516 added to reporting queue: Trace path-traversal: TRACE 884 (881)
              new PatternMetadata(
                      "toRptQueue",
                      List.of(" added to reporting queue: Trace"),
                      Pattern.compile(
                              DEBUG_PREAMBLE_XTRACT
                                      + "- Trace " + TRACE_HASH_XTRACT
                                      + " added to reporting queue: "
                                      // TODO what is the second trace number?
                                      + "Trace " + RULE_XTRACT + ": TRACE " + TRACE_XTRACT + " \\(\\d+\\)"
                                      + "$")),
              // 2024-11-20 15:38:47,945 [reactor-http-nio-2 AMQP Publisher] DEBUG - MQPublisherImpl#publish call: exchangeName: , queueName: -00000-V5_1.it_tests_sources_V5, properties: #contentHeader<basic>(...)
              // , body: {"hash":3277375950,"version":4,"session_id":"AcceptanceTestSessionId","ruleId":"path-traversal",
               new PatternMetadata(
                      "mqpublish",
                      List.of("- MQPublisherImpl#publish call:", "type=FINDING_DISCOVERED," ),
                      Pattern.compile(
                                DEBUG_PREAMBLE_XTRACT
                                      + "- MQPublisherImpl#publish call: queueName: " + RPT_QUEUE_XTRACT
                                      + ", properties:[^(]+" + "\\([^)]+\\)"
                                      + ", body: \\{\"hash\":"
                                      + TRACE_HASH_XTRACT + ",\"version\":.+?,\"ruleId\":\""
                                      + RULE_XTRACT + "\","
                                      + ".+\"standardNormalizedUri\":\"(?<" + URL_VAR + ">[^\"]+)\",.+"
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
                                      + "$"))
      );

  public VulnShred() {
    super(SHRED_METADATA, SHRED_SQL_TABLE,
            MISFITS_METADATA, MISFITS_SQL_TABLE,
            ENTRY_SIGNATURES, PATTERN_METADATA,
            true);
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
      "2024-12-23 19:21:27,552 [reactor-http-nio-1 AMQP_Publisher] DEBUG - MQPublisherImpl#publish call: queueName: -com.contrastsecurity.agent.test.assess.spring.async.SpringWebFluxIT$V5_1, " +
              "properties: #contentHeader<basic>(content-type=null, content-encoding=null, headers=null, delivery-mode=null, priority=null, correlation-id=null, reply-to=null, expiration=null, message-id=null, timestamp=null, " +
              "type=FINDING_DISCOVERED, user-id=null, app-id=null, cluster-id=null)" +
              ", body: {\"hash\":3606565643,\"version\":4,\"session_id\":\"AcceptanceTestSessionId\",\"ruleId\":\"httponly\",\"properties\":{},\"events\":[{\"action\":\"TRIGGER\",\"type\":\"METHOD\",\"time\":1734981687551,\"thread\":\"reactor-http-nio-1 (id 31)\",\"source\":\"P2,P3\",\"object\":{\"hash\":1298051484,\"tracked\":false,\"value\":\"aW8ubmV0dHkuaGFuZGxlci5jb2RlYy5EZWZhdWx0SGVhZGVyc0ltcGxANGQ1ZWIxOWM\\u003d\"},\"args\":[{\"hash\":1032738388,\"tracked\":false,\"value\":\"LTExMDczODY1MjU\\u003d\"},{\"hash\":696427459,\"tracked\":false,\"value\":\"Mw\\u003d\\u003d\"},{\"hash\":-1980420497,\"tracked\":false,\"value\":\"U2V0LUNvb2tpZQ\\u003d\\u003d\"},{\"hash\":166722180,\"tracked\":false,\"value\":\"TXlDb29raWU9VmFsdWU\\u003d\"}],\"ret\":{\"hash\":0,\"tracked\":false,\"value\":\"bnVsbA\\u003d\\u003d\"},\"stack\":[{\"signature\":\"io.netty.handler.codec.DefaultHeaders.add0(DefaultHeaders.java:976)\",\"method\":\"add0\",\"file\":\"DefaultHeaders.java\",\"lineNumber\":976},{\"signature\":\"io.netty.handler.codec.DefaultHeaders.add(DefaultHeaders.java:299)\",\"method\":\"add\",\"file\":\"DefaultHeaders.java\",\"lineNumber\":299},{\"signature\":\"io.netty.handler.codec.DefaultHeaders.addObject(DefaultHeaders.java:327)\",\"method\":\"addObject\",\"file\":\"DefaultHeaders.java\",\"lineNumber\":327},{\"signature\":\"io.netty.handler.codec.http.DefaultHttpHeaders.add(DefaultHttpHeaders.java:135)\",\"method\":\"add\",\"file\":\"DefaultHttpHeaders.java\",\"lineNumber\":135},{\"signature\":\"io.netty.handler.codec.http.HttpObjectDecoder.readHeaders(HttpObjectDecoder.java:611)\",\"method\":\"readHeaders\",\"file\":\"HttpObjectDecoder.java\",\"lineNumber\":611},{\"signature\":\"io.netty.handler.codec.http.HttpObjectDecoder.decode(HttpObjectDecoder.java:258)\",\"method\":\"decode\",\"file\":\"HttpObjectDecoder.java\",\"lineNumber\":258},{\"signature\":\"io.netty.handler.codec.http.HttpClientCodec$Decoder.decode(HttpClientCodec.java:225)\",\"method\":\"decode\",\"file\":\"HttpClientCodec.java\",\"lineNumber\":225},{\"signature\":\"io.netty.handler.codec.ByteToMessageDecoder.decodeRemovalReentryProtection(ByteToMessageDecoder.java:501)\",\"method\":\"decodeRemovalReentryProtection\",\"file\":\"ByteToMessageDecoder.java\",\"lineNumber\":501},{\"signature\":\"io.netty.handler.codec.ByteToMessageDecoder.callDecode(ByteToMessageDecoder.java:440)\",\"method\":\"callDecode\",\"file\":\"ByteToMessageDecoder.java\",\"lineNumber\":440},{\"signature\":\"io.netty.handler.codec.ByteToMessageDecoder.channelRead(ByteToMessageDecoder.java:276)\",\"method\":\"channelRead\",\"file\":\"ByteToMessageDecoder.java\",\"lineNumber\":276},{\"signature\":\"io.netty.channel.CombinedChannelDuplexHandler.channelRead(CombinedChannelDuplexHandler.java:251)\",\"method\":\"channelRead\",\"file\":\"CombinedChannelDuplexHandler.java\",\"lineNumber\":251},{\"signature\":\"io.netty.channel.AbstractChannelHandlerContext.invokeChannelRead(AbstractChannelHandlerContext.java:379)\",\"method\":\"invokeChannelRead\",\"file\":\"AbstractChannelHandlerContext.java\",\"lineNumber\":379},{\"signature\":\"io.netty.channel.AbstractChannelHandlerContext.invokeChannelRead(AbstractChannelHandlerContext.java:365)\",\"method\":\"invokeChannelRead\",\"file\":\"AbstractChannelHandlerContext.java\",\"lineNumber\":365},{\"signature\":\"io.netty.channel.AbstractChannelHandlerContext.fireChannelRead(AbstractChannelHandlerContext.java:357)\",\"method\":\"fireChannelRead\",\"file\":\"AbstractChannelHandlerContext.java\",\"lineNumber\":357},{\"signature\":\"io.netty.channel.DefaultChannelPipeline$HeadContext.channelRead(DefaultChannelPipeline.java:1410)\",\"method\":\"channelRead\",\"file\":\"DefaultChannelPipeline.java\",\"lineNumber\":1410},{\"signature\":\"io.netty.channel.AbstractChannelHandlerContext.invokeChannelRead(AbstractChannelHandlerContext.java:379)\",\"method\":\"invokeChannelRead\",\"file\":\"AbstractChannelHandlerContext.java\",\"lineNumber\":379},{\"signature\":\"io.netty.channel.AbstractChannelHandlerContext.invokeChannelRead(AbstractChannelHandlerContext.java:365)\",\"method\":\"invokeChannelRead\",\"file\":\"AbstractChannelHandlerContext.java\",\"lineNumber\":365},{\"signature\":\"io.netty.channel.DefaultChannelPipeline.fireChannelRead(DefaultChannelPipeline.java:919)\",\"method\":\"fireChannelRead\",\"file\":\"DefaultChannelPipeline.java\",\"lineNumber\":919},{\"signature\":\"io.netty.channel.nio.AbstractNioByteChannel$NioByteUnsafe.read(AbstractNioByteChannel.java:166)\",\"method\":\"read\",\"file\":\"AbstractNioByteChannel.java\",\"lineNumber\":166},{\"signature\":\"io.netty.channel.nio.NioEventLoop.processSelectedKey(NioEventLoop.java:714)\",\"method\":\"processSelectedKey\",\"file\":\"NioEventLoop.java\",\"lineNumber\":714},{\"signature\":\"io.netty.channel.nio.NioEventLoop.processSelectedKeysOptimized(NioEventLoop.java:650)\",\"method\":\"processSelectedKeysOptimized\",\"file\":\"NioEventLoop.java\",\"lineNumber\":650},{\"signature\":\"io.netty.channel.nio.NioEventLoop.processSelectedKeys(NioEventLoop.java:576)\",\"method\":\"processSelectedKeys\",\"file\":\"NioEventLoop.java\",\"lineNumber\":576},{\"signature\":\"io.netty.channel.nio.NioEventLoop.run(NioEventLoop.java:493)\",\"method\":\"run\",\"file\":\"NioEventLoop.java\",\"lineNumber\":493},{\"signature\":\"io.netty.util.concurrent.SingleThreadEventExecutor$4.run(SingleThreadEventExecutor.java:989)\",\"method\":\"run\",\"file\":\"SingleThreadEventExecutor.java\",\"lineNumber\":989},{\"signature\":\"java.base/java.lang.ContrastRunnableWrapper.run(ContrastRunnableWrapper.java:42)\",\"method\":\"run\",\"file\":\"ContrastRunnableWrapper.java\",\"lineNumber\":42},{\"signature\":\"io.netty.util.internal.ThreadExecutorMap$2.run(ThreadExecutorMap.java:74)\",\"method\":\"run\",\"file\":\"ThreadExecutorMap.java\",\"lineNumber\":74},{\"signature\":\"java.base/java.lang.ContrastRunnableWrapper.run(ContrastRunnableWrapper.java:42)\",\"method\":\"run\",\"file\":\"ContrastRunnableWrapper.java\",\"lineNumber\":42},{\"signature\":\"io.netty.util.concurrent.FastThreadLocalRunnable.run(FastThreadLocalRunnable.java:30)\",\"method\":\"run\",\"file\":\"FastThreadLocalRunnable.java\",\"lineNumber\":30},{\"signature\":\"java.base/java.lang.Thread.run(Unknown Source)\",\"method\":\"run\",\"lineNumber\":-1}],\"tags\":\"\",\"summary\":false,\"signature\":{\"returnType\":\"void\",\"className\":\"io.netty.handler.codec.DefaultHeaders\",\"methodName\":\"add0\",\"argTypes\":[\"int\",\"int\",\"java.lang.Object\",\"java.lang.Object\"],\"constructor\":false,\"flags\":2},\"taintRanges\":[],\"objectId\":0}],\"routes\":[]}"
  );
  
  public static void main(String[] args) {
    testPatternMatching(exampleLogLines, PATTERN_METADATA, true);
  }
}
