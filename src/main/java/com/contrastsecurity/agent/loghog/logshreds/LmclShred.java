/* (C)2024 */
package com.contrastsecurity.agent.loghog.logshreds;

public class LmclShred /* extends AbstractShred */ {

  //    public LmclShred() {
  //        super(
  //                new SqlTableBase(
  //                        LMCL_TBL_NAME, LMCL_TBL_CREATE_SQL, LMCL_TBL_INDEX_SQLS,
  // LMCL_TBL_COLUMNS),
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
  //            int line, String entry, String type, Map<String, Object> extractedVals) {
  //        String[] classAndPackage = classAndPackage((String) extractedVals.get("fqcn"));
  //        String classname = classAndPackage[0];
  //        String packageName = classAndPackage[1];
  //        return new Object[] {
  //            line,
  //            classname,
  //            packageName,
  //            extractedVals.get("result"),
  //            extractedVals.get("location"),
  //            extractedVals.get("adapters")
  //        };
  //    }
  //
  //    private String[] classAndPackage(String fqcn) {
  //        int lastDotIndex = fqcn.lastIndexOf('.');
  //        if (lastDotIndex == -1) {
  //            return new String[] {fqcn, ""};
  //        }
  //        String classname = fqcn.substring(lastDotIndex + 1);
  //        String packageName = fqcn.substring(0, lastDotIndex);
  //        return new String[] {classname, packageName};
  //    }
  //
  //    @Override
  //    public Object[] transformMisfits(int line, int lastGoodLine) {
  //        return new Object[] {line};
  //    }
  //
  //    // AbstractShred table "lmcl" (class load)
  //    public static final String LMCL_TBL_NAME = "lmcl";
  //    public static final String LMCL_TBL_CREATE_SQL =
  //            "create table lmcl("
  //                    + "line integer primary key references log(line),"
  //                    + "class text not null,"
  //                    + "package text not null,"
  //                    + "result text,"
  //                    + "location text,"
  //                    + "adapters text)";
  //    public static final List<String> LMCL_TBL_INDEX_SQLS =
  //            Arrays.asList(
  //                    "create index idx_lmcl_package on lmcl(package)",
  //                    "create index idx_lmcl_class_package on lmcl(class, package)");
  //    public static final List<String> LMCL_TBL_COLUMNS =
  //            Arrays.asList("line", "class", "package", "result", "adapters");
  //
  //    public static final String ENTRY_SIGNATURE = "!LM!ClassLoad|";
  //    public static final ShredEntrySelector ENTRY_SELECTOR = new
  // ShredEntrySelector(ENTRY_SIGNATURE);
  //
  //    public static final ShredEntryClassifier ENTRY_CLASSIFIER = new ShredEntryClassifier();
  //
  //    public static final List<String> EXTRACTED_VAL_NAMES =
  //            Arrays.asList("fqcn", "result", "adapters", "location");
  //    public static final Map<String, Pattern> VALUE_EXTRACTORS =
  //            new HashMap<String, Pattern>() {
  //                {
  //                    put(
  //                            AbstractShred.DEFAULT_TYPE,
  //                            Pattern.compile(
  //
  // "!LM!ClassLoad\\|(?<fqcn>[^|]+)\\|result=(?<result>[^&]+)&adapters=(?<adapters>[^&]*)&location=(?<location>.*)$"));
  //                }
  //            };
  //    public static final ShredValueExtractor VALUE_EXTRACTOR =
  //            new ShredValueExtractor(EXTRACTED_VAL_NAMES, VALUE_EXTRACTORS);
  //
  //    // AbstractShred misfits table "lmcl_misfits"
  //    public static final String MISFITS_TBL_NAME = "lmcl_misfits";
  //    public static final String MISFITS_TBL_CREATE_SQL =
  //            "create table lmcl_misfits(" + "line integer primary key references log(line))";
  //    public static final List<String> MISFITS_TBL_INDEX_SQLS = List.of();
  //    public static final List<String> MISFITS_TBL_COLUMNS = Arrays.asList("line");
}
