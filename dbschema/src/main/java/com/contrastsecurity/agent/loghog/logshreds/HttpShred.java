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
                                  + NO_REQ_XTRACT + NO_RESP_XTRACT + NO_NATIVE_RESP_XTRACT + NO_OUTPUT_MECHANISM_XTRACT + "$")),
          //Capturing response to memory
          new PatternMetadata(
              "respCapture",
              List.of("Capturing response to memory"),
              Pattern.compile(DEBUG_PREAMBLE_XTRACT + "- Capturing response to memory"
                      + NO_REQ_XTRACT + NO_RESP_XTRACT + NO_URL_XTRACT + NO_NATIVE_RESP_XTRACT + NO_OUTPUT_MECHANISM_XTRACT + "$")),
          //2024-11-07 18:04:50,774 [reactor-http-nio-4 HttpManager] DEBUG - Request ending for /auto-binding/v1_0/autobind-unsafe - response is k@2a7ec4a7 and output mechanism is null
          // FIXME OUTPUT_MECHANISM reports the string null instead of a null value
          new PatternMetadata(
              "reqEnding",
              List.of("- Request ending for "),
              Pattern.compile(DEBUG_PREAMBLE_XTRACT + "- Request ending for " + URL_XTRACT + " - response is "
                      + NATIVE_RESP_XTRACT +  " and output mechanism is "  + OUTPUT_MECHANISM_XTRACT
                      + NO_REQ_XTRACT + NO_RESP_XTRACT + "$")),
          //Response was empty for URI /sources/v5_0/matrixVariable/foo;var=strawberries
          new PatternMetadata(
              "respEmpty",
              List.of("Response was empty for "),
              Pattern.compile(DEBUG_PREAMBLE_XTRACT + "- Response was empty for URI " + URL_XTRACT +
                      NO_REQ_XTRACT + NO_RESP_XTRACT + NO_NATIVE_RESP_XTRACT + NO_OUTPUT_MECHANISM_XTRACT + "$"))
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
    super(SHRED_METADATA, SHRED_SQL_TABLE, MISFITS_METADATA, MISFITS_SQL_TABLE, SHRED_SOURCE);
  }

  public static void main(String[] args) {
    final String matchThis =
            "2024-11-07 18:04:50,774 [reactor-http-nio-4 HttpManager] DEBUG - Request ending for /auto-binding/v1_0/autobind-unsafe - response is k@2a7ec4a7 and output mechanism is null";

    final Pattern toTest =
            PATTERN_METADATA.stream()
                    .filter(pmd -> "reqEnding".equals(pmd.patternId()))
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
