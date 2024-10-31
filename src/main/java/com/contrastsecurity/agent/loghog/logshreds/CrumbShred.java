/* (C)2024 */
package com.contrastsecurity.agent.loghog.logshreds;

import com.contrastsecurity.agent.loghog.sql.SqlTableBase;

public class CrumbShred /* extends AbstractShred */ {
//
//    public CrumbShred() {
//        super(
//                new SqlTableBase(
//                        CRUMB_TBL_NAME,
//                        CRUMB_TBL_CREATE_SQL,
//                        CRUMB_TBL_INDEX_SQLS,
//                        CRUMB_TBL_COLUMNS),
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
//        return new Object[] {
//            line,
//            extractedVals.get(TIMESTAMP_VAR),
//            extractedVals.get(THREAD_VAR),
//            extractedVals.get(LOGGER_VAR),
//            extractedVals.get(LEVEL_VAR),
//            extractedVals.get("message")
//        };
//    }
//
//    @Override
//    public Object[] transformMisfits(int line, int lastGoodLine) {
//        return new Object[] {line};
//    }
//
//    // AbstractShred table "crumb"
//    public static final String CRUMB_TBL_NAME = "crumb";
//    public static final String CRUMB_TBL_CREATE_SQL =
//            """
//create table crumb(
//    line integer primary key references log(line),
//    pattern text,
//    req text,
//    resp text,
//    url text,
//    thread text,
//    timestamp datetime,
//    stackframe text)
//""";
//    public static final List<String> CRUMB_TBL_INDEX_SQLS =
//            Arrays.asList("create index idx_crumb_url on crumb(url)");
//    public static final List<String> CRUMB_TBL_COLUMNS =
//            Arrays.asList(
//                    "line", "type", "req", "resp", "url", "thread", "timestamp", "stackframe");
//
//    // Selects all "CRUMB" lines from log table
//    public static final String ENTRY_SIGNATURE = " CRUMB ";
//    public static final ShredEntrySelector ENTRY_SELECTOR = new ShredEntrySelector(ENTRY_SIGNATURE);
//
//    public static final Map<String, List<String>> PATTERN_SIGNATURES =
//            new HashMap<String, List<String>>() {
//                {
//                    put("hist_req_begin", Arrays.asList("request@", "\t\t\tBEGIN "));
//                    put("req_begin", Arrays.asList("request@", "\t\tBEGIN "));
//                    put("hist_resp_begin", Arrays.asList("response@", "\t\t\tBEGIN "));
//                    put("resp_begin", Arrays.asList("response@", "\t\tBEGIN "));
//                    put("req_end", Arrays.asList("request@", "END & HISTORY:"));
//                    put("resp_end", Arrays.asList("response@", "END & HISTORY:"));
//                }
//            };
//    public static final ShredEntryClassifier ENTRY_CLASSIFIER =
//            new ShredEntryClassifier(PATTERN_SIGNATURES);
//
//    public static final List<String> EXTRACTED_VAL_NAMES =
//            Arrays.asList(REQ_VAR, RESP_VAR, URL_VAR, THREAD_VAR, TIMESTAMP_VAR, STACKFRAME_VAR);
//    public static final Map<String, Pattern> VALUE_EXTRACTORS =
//            new HashMap<String, Pattern>() {
//                {
//                    put(
//                            "hist_req_begin",
//                            Pattern.compile(
//                                    DEBUG_PREAMBLE_XTRACT
//                                            + "- CRUMB "
//                                            + REQ_XTRACT
//                                            + " "
//                                            + URL_XTRACT
//                                            + "\\t\\t\\tBEGIN.+"
//                                            + NO_RESP_XTRACT
//                                            + NO_STACKFRAME_XTRACT
//                                            + "$"));
//                    put(
//                            "req_begin",
//                            Pattern.compile(
//                                    DEBUG_PREAMBLE_XTRACT
//                                            + "- CRUMB "
//                                            + REQ_XTRACT
//                                            + " "
//                                            + URL_XTRACT
//                                            + "\\t\\tBEGIN.+"
//                                            + NO_RESP_XTRACT
//                                            + NO_STACKFRAME_XTRACT
//                                            + "$"));
//                    put(
//                            "hist_resp_begin",
//                            Pattern.compile(
//                                    DEBUG_PREAMBLE_XTRACT
//                                            + "- CRUMB "
//                                            + RESP_XTRACT
//                                            + " \\t\\t\\tBEGIN.+"
//                                            + NO_REQ_XTRACT
//                                            + NO_URL_XTRACT
//                                            + NO_STACKFRAME_XTRACT
//                                            + "$"));
//                    put(
//                            "resp_begin",
//                            Pattern.compile(
//                                    DEBUG_PREAMBLE_XTRACT
//                                            + "- CRUMB "
//                                            + RESP_XTRACT
//                                            + " \\t\\tBEGIN.+"
//                                            + NO_REQ_XTRACT
//                                            + NO_URL_XTRACT
//                                            + NO_STACKFRAME_XTRACT
//                                            + "$"));
//                    put(
//                            "req_end",
//                            Pattern.compile(
//                                    DEBUG_PREAMBLE_XTRACT
//                                            + "- CRUMB "
//                                            + REQ_XTRACT
//                                            + " "
//                                            + URL_XTRACT
//                                            + " END & HISTORY:"
//                                            + NO_RESP_XTRACT
//                                            + NO_STACKFRAME_XTRACT
//                                            + "$"));
//                    put(
//                            "resp_end",
//                            Pattern.compile(
//                                    DEBUG_PREAMBLE_XTRACT
//                                            + "- CRUMB "
//                                            + RESP_XTRACT
//                                            + " END & HISTORY:"
//                                            + NO_REQ_XTRACT
//                                            + NO_URL_XTRACT
//                                            + NO_STACKFRAME_XTRACT
//                                            + "$"));
//                    put(AbstractShred.DEFAULT_TYPE, Pattern.compile("^~NOMATCH~$"));
//                }
//            };
//    public static final ShredValueExtractor VALUE_EXTRACTOR =
//            new ShredValueExtractor(EXTRACTED_VAL_NAMES, VALUE_EXTRACTORS);
//
//    // AbstractShred misfits table "crumb_misfits"
//    public static final String MISFITS_TBL_NAME = "crumb_misfits";
//    public static final String MISFITS_TBL_CREATE_SQL =
//            "create table crumb_misfits(" + "line integer primary key references log(line))";
//    public static final List<String> MISFITS_TBL_INDEX_SQLS = List.of();
//    public static final List<String> MISFITS_TBL_COLUMNS = Arrays.asList("line");
}
