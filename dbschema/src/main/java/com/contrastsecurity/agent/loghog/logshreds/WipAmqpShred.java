/* (C)2024 */
package com.contrastsecurity.agent.loghog.logshreds;

public class WipAmqpShred /* extends BaseShred */ {

  //    public WipAmqpShred() {
  //        super(
  //                new SqlTableBase(
  //                        AMQP_TBL_NAME, AMQP_TBL_CREATE_SQL, AMQP_TBL_INDEX_SQLS,
  // AMQP_TBL_COLUMNS),
  //                new SqlTableBase(
  //                        MISFITS_TBL_NAME,
  //                        MISFITS_TBL_CREATE_SQL,
  //                        MISFITS_TBL_INDEX_SQLS,
  //                        MISFITS_TBL_COLUMNS),
  //                ENTRY_SELECTOR,
  //                ENTRY_CLASSIFIER,
  //                VALUE_EXTRACTOR);
  //    }
  //
  //    @Override
  //    public Object[] transformValues(
  //            int line, String entry, String patternId, Map<String, Object> extractedVals) {
  //        Matcher match = TYPE_EXTRACTOR.matcher(entry);
  //        if (match.find()) {
  //            return new Object[] {
  //                line,
  //                match.group("type"),
  //                extractedVals.get("exchangeName"),
  //                extractedVals.get("queueName"),
  //                extractedVals.get("properties"),
  //                extractedVals.get("body")
  //            };
  //        }
  //        return new Object[] {
  //            line,
  //            null,
  //            extractedVals.get("exchangeName"),
  //            extractedVals.get("queueName"),
  //            extractedVals.get("properties"),
  //            extractedVals.get("body")
  //        };
  //    }
  //
  //    @Override
  //    public Object[] transformMisfits(int line, int lastGoodLine) {
  //        return new Object[] {line};
  //    }
  //
  //    // BaseShred table "amqp" (message queue)
  //    public static final String AMQP_TBL_NAME = "amqp";
  //    public static final String AMQP_TBL_CREATE_SQL =
  //            "create table amqp("
  //                    + "line integer primary key references log(line),"
  //                    + "type text not null,"
  //                    + "exchangeName text not null,"
  //                    + "queueName text not null,"
  //                    + "properties text not null,"
  //                    + "body text not null)";
  //    public static final List<String> AMQP_TBL_INDEX_SQLS = Collections.emptyList();
  //    public static final List<String> AMQP_TBL_COLUMNS =
  //            Arrays.asList("line", "type", "exchangeName", "queueName", "properties", "body");
  //
  //    public static final String ENTRY_SIGNATURE =
  //            "AMQP Publisher] DEBUG - MQPublisherImpl#publish call: exchangeName:";
  //    public static final ShredEntrySelector ENTRY_SELECTOR = new
  // ShredEntrySelector(ENTRY_SIGNATURE);
  //
  //    public static final ShredEntryClassifier ENTRY_CLASSIFIER =
  //            new ShredEntryClassifier(); // just one default type
  //
  //    public static final List<String> EXTRACTED_VAL_NAMES =
  //            Arrays.asList("exchangeName", "queueName", "properties", "body");
  //    public static final Map<String, Pattern> VALUE_EXTRACTORS =
  //            new HashMap<String, Pattern>() {
  //                {
  //                    put(
  //                            BaseShred.DEFAULT_TYPE,
  //                            Pattern.compile(
  //                                    "^.* AMQP Publisher] DEBUG - MQPublisherImpl#publish
  // call:"
  //                                            + " exchangeName: (?<exchangeName>[^,]*),
  // queueName:"
  //                                            + " (?<queueName>[^,]*), properties:
  // (?<properties>.*),"
  //                                            + " body: (?<body>.*)$"));
  //                }
  //            };
  //    public static final ShredValueExtractor VALUE_EXTRACTOR =
  //            new ShredValueExtractor(EXTRACTED_VAL_NAMES, VALUE_EXTRACTORS);
  //
  //    public static final Pattern TYPE_EXTRACTOR = Pattern.compile(".*, type=(?<type>[^,]+), ");
  //
  //    // BaseShred misfits table "amqp_misfits"
  //    public static final String MISFITS_TBL_NAME = "amqp_misfits";
  //    public static final String MISFITS_TBL_CREATE_SQL =
  //            "create table amqp_misfits(" + "line integer primary key references log(line))";
  //    public static final List<String> MISFITS_TBL_INDEX_SQLS = List.of();
  //    public static final List<String> MISFITS_TBL_COLUMNS = Arrays.asList("line");
}
