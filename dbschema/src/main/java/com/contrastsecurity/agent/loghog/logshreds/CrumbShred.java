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
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.FROM_THREAD_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.FROM_THREAD_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_FROM_THREAD_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_REQ_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_RESP_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_STACKFRAME_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.NO_URL_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.REQ_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.REQ_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.RESP_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.RESP_XTRACT;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.STACKFRAME_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.THREAD_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.TIMESTAMP_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.URL_VAR;
import static com.contrastsecurity.agent.loghog.logshreds.PatternGroups.URL_XTRACT;

public class CrumbShred extends BaseShred {

  static final String SHRED_TABLE_NAME = "CRUMB";
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
          new ShredRowMetaData("STACKFRAME", SQLDataType.VARCHAR, String.class, STACKFRAME_VAR),
          new ShredRowMetaData("FROM_THREAD", SQLDataType.VARCHAR, String.class, FROM_THREAD_VAR));

  static final String MISFITS_TABLE_NAME = "CRUMB_MISFITS";
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
          " CRUMB "
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

  static final String CRUMB_REQ_PREFIX =
      DEBUG_PREAMBLE_XTRACT + "- CRUMB " + REQ_XTRACT + " " + URL_XTRACT;
  static final String CRUMB_REQ_SUFFIX = NO_RESP_XTRACT + NO_STACKFRAME_XTRACT;
  static final String CRUMB_RESP_PREFIX = DEBUG_PREAMBLE_XTRACT + "- CRUMB " + RESP_XTRACT + " ";
  static final String CRUMB_RESP_SUFFIX =
      NO_REQ_XTRACT + NO_URL_XTRACT + NO_STACKFRAME_XTRACT ;

  static final List<PatternMetadata> PATTERN_METADATA =
      List.of(
          new PatternMetadata(
              "histReqBegin",
              List.of("request@", "\t\t\tBEGIN "),
              Pattern.compile(CRUMB_REQ_PREFIX + "\\t\\t\\tBEGIN .*" + CRUMB_REQ_SUFFIX + NO_FROM_THREAD_XTRACT+ "$")),
          new PatternMetadata(
              "reqBegin",
              List.of("request@", "\t\tBEGIN "),
              Pattern.compile(CRUMB_REQ_PREFIX + "\\t\\tBEGIN .*" + CRUMB_REQ_SUFFIX + NO_FROM_THREAD_XTRACT+ "$")),
          new PatternMetadata(
              "histRespBegin",
              List.of("response@", "\t\t\tBEGIN "),
              Pattern.compile(CRUMB_RESP_PREFIX + "\\t\\t\\tBEGIN .*" + CRUMB_RESP_SUFFIX + NO_FROM_THREAD_XTRACT+ "$")),
          new PatternMetadata(
              "respBegin",
              List.of("response@", "\t\tBEGIN "),
              Pattern.compile(CRUMB_RESP_PREFIX + "\\t\\tBEGIN .*" + CRUMB_RESP_SUFFIX + NO_FROM_THREAD_XTRACT+ "$")),
          new PatternMetadata(
              "reqEndHist",
              List.of("request@", "END & HISTORY:"),
              Pattern.compile(CRUMB_REQ_PREFIX + " END & HISTORY:" + CRUMB_REQ_SUFFIX + NO_FROM_THREAD_XTRACT+ "$")),
          new PatternMetadata(
              "respEndHist",
              List.of("response@", "END & HISTORY:"),
              Pattern.compile(CRUMB_RESP_PREFIX + " END & HISTORY:" + CRUMB_RESP_SUFFIX + NO_FROM_THREAD_XTRACT+ "$")),
          new PatternMetadata(
                  "reqEnd",
                  List.of("request@", "\tEND 20"),
                  Pattern.compile(CRUMB_REQ_PREFIX + " END 20.*" + CRUMB_REQ_SUFFIX + NO_FROM_THREAD_XTRACT+ "$")),
          new PatternMetadata(
                  "respEnd",
                  List.of("response@", "\tEND 20"),
                  Pattern.compile(CRUMB_RESP_PREFIX + " END 20.*" + CRUMB_RESP_SUFFIX + NO_FROM_THREAD_XTRACT+ "$")),
              // 2024-10-28 14:36:24,863 [main b] DEBUG - io.netty.channel.nio.NioEventLoop@f8cd5d7
              // wrapped a runnable: io.netty.channel.AbstractChannel$AbstractUnsafe$1@4d1d30dc
              new PatternMetadata(
                      "contextSwitchReqHist",
                      List.of("\t\t\tCONTEXT_SWITCH"),
                      Pattern.compile(
                              CRUMB_REQ_PREFIX
                                      + "\t\t\tCONTEXT_SWITCH \\S+ \\S+ "
                                      + FROM_THREAD_XTRACT
                                      + " ==> \\S+"
                                      + CRUMB_REQ_SUFFIX
                                      + "$")),
              // 2024-11-07 18:04:50,407 [reactor-http-nio-1 b] DEBUG
              // - CRUMB request@606865888 /client/v5_0/mono-body		CONTEXT_SWITCH 2024-11-07 18:04:50,407 reactor-http-nio-4 ==> reactor-http-nio-1
              new PatternMetadata(
                      "contextSwitchReq",
                      List.of("\t\tCONTEXT_SWITCH"),
                      Pattern.compile(
                              CRUMB_REQ_PREFIX
                                      + "\t\tCONTEXT_SWITCH \\S+ \\S+ "
                                      + FROM_THREAD_XTRACT
                                      + " ==> \\S+"
                                      + CRUMB_REQ_SUFFIX
                                      + "$")),
              // 2024-10-28 14:36:24,863 [main b] DEBUG - io.netty.channel.nio.NioEventLoop@f8cd5d7
              // wrapped a runnable: io.netty.channel.AbstractChannel$AbstractUnsafe$1@4d1d30dc
              new PatternMetadata(
                      "contextSwitchRespHist",
                      List.of("\t\t\tCONTEXT_SWITCH"),
                      Pattern.compile(
                              CRUMB_RESP_PREFIX
                                      + "\t\t\tCONTEXT_SWITCH \\S+ \\S+ "
                                      + FROM_THREAD_XTRACT
                                      + " ==> \\S+"
                                      + CRUMB_RESP_SUFFIX
                                      + "$")),
              // 2024-11-07 18:04:51,077 [reactor-http-nio-4 b] DEBUG - CRUMB response@2147333596 		CONTEXT_SWITCH 2024-11-07 18:04:51,077 reactor-http-nio-2 ==> reactor-http-nio-4
              new PatternMetadata(
                      "contextSwitchResp",
                      List.of("\t\tCONTEXT_SWITCH"),
                      Pattern.compile(
                              CRUMB_RESP_PREFIX
                                      + "\t\tCONTEXT_SWITCH \\S+ \\S+ "
                                      + FROM_THREAD_XTRACT
                                      + " ==> \\S+"
                                      + CRUMB_RESP_SUFFIX
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

  public static final BaseShredSource SHRED_SOURCE =
      new BaseShredSource(
          LOG_TABLE_NAME,
          VALUE_EXTRACTOR,
          ROW_CLASSIFIER,
          jooq().select(DSL.asterisk()).from(LOG_TABLE_NAME).where(entryTestSql()).getSQL());

  public CrumbShred() {
    super(SHRED_METADATA, SHRED_SQL_TABLE, MISFITS_METADATA, MISFITS_SQL_TABLE, SHRED_SOURCE);
  }

  public static void main(String[] args) {
    final String matchThis =
            "2024-11-11 20:06:16,284 [reactor-http-nio-2 HttpManager] DEBUG - HttpContext{HttpRequest@40d46f1f, k@52e20455} - Request ending for /ping - response is k@52e20455 and output mechanism is null";

    final Pattern toTest =
            PATTERN_METADATA.stream()
                    .filter(pmd -> "reqEndingFor".equals(pmd.patternId()))
                    .map(PatternMetadata::pattern)
                    .findFirst()
                    .orElseGet(null);
    System.out.println("Pattern: " + toTest);
    System.out.println("Matches? " + matchThis);
    Matcher matcher = toTest.matcher(matchThis);
    System.out.println(" = " + matcher.matches());
    if (matcher.matches()) {
      for (Map.Entry<String, Integer> entry : matcher.namedGroups().entrySet()) {
        final String name = entry.getKey();
        final Integer groupIdx = entry.getValue();
        System.out.println(
                "group("
                        + name
                        + ") -> \'"
                        + String.valueOf(matcher.group(groupIdx))
                        + "\'"
                        + " == null ? "
                        + String.valueOf(matcher.group(name) == null));
      }
    }
  }

}
