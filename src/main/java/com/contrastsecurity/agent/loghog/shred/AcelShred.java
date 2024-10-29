/* (C)2024 */
package com.contrastsecurity.agent.loghog.shred;

import com.contrastsecurity.agent.loghog.sql.SqlTableBase;
import java.util.*;
import java.util.regex.Pattern;

public class AcelShred extends Shred {

    public AcelShred() {
        super(
                new SqlTableBase(
                        ACEL_TBL_NAME, ACEL_TBL_CREATE_SQL, ACEL_TBL_INDEX_SQLS, ACEL_TBL_COLUMNS),
                new SqlTableBase(
                        MISFITS_TBL_NAME,
                        MISFITS_TBL_CREATE_SQL,
                        MISFITS_TBL_INDEX_SQLS,
                        MISFITS_TBL_COLUMNS),
                ENTRY_SELECTOR,
                ENTRY_CLASSIFIER,
                VALUE_EXTRACTOR);
    }

    @Override
    public Object[] transformValues(
            int line, String entry, String patternId, Map<String, Object> extractedVals) {
        String[] classAndPackage = classAndPackage((String) extractedVals.get("fqcn"));
        String classname = classAndPackage[0];
        String packageName = classAndPackage[1];
        return new Object[] {
            line,
            patternId,
            classname,
            packageName,
            extractedVals.get("application"),
            extractedVals.get("location")
        };
    }

    private String[] classAndPackage(String fqcn) {
        int lastDotIndex = fqcn.lastIndexOf('.');
        if (lastDotIndex == -1) {
            return new String[] {fqcn, ""};
        }
        String classname = fqcn.substring(lastDotIndex + 1);
        String packageName = fqcn.substring(0, lastDotIndex);
        return new String[] {classname, packageName};
    }

    @Override
    public Object[] transformMisfits(int line, int lastGoodLine) {
        return new Object[] {line};
    }

    // Shred table "acel" (message queue)
    public static final String ACEL_TBL_NAME = "acel";
    public static final String ACEL_TBL_CREATE_SQL =
            "create table acel("
                    + "line integer primary key references log(line),"
                    + "class text not null,"
                    + "package text not null,"
                    + "application text,"
                    + "location text)";
    public static final List<String> ACEL_TBL_INDEX_SQLS =
            Arrays.asList(
                    "create index idx_acel_package on acel(package)",
                    "create index idx_acel_class_package on acel(class, package)");
    public static final List<String> ACEL_TBL_COLUMNS =
            Arrays.asList("line", "class", "package", "application", "location");

    public static final String ENTRY_SIGNATURE = " ApplicationClassEventListener] ";
    public static final ShredEntrySelector ENTRY_SELECTOR = new ShredEntrySelector(ENTRY_SIGNATURE);

    public static final Map<String, List<String>> PATTERN_SIGNATURES =
            new HashMap<String, List<String>>() {
                {
                    put("noput", Arrays.asList("- Not putting "));
                    put("noapp", Arrays.asList("- Couldn't find app for "));
                    put("orphan", Arrays.asList(" to orphanage"));
                    put("uninventoried", Arrays.asList("missed classload events"));
                    put("contains", Arrays.asList("- url @detectLibraryClass"));
                    put("nolib", Arrays.asList("- No library found"));
                    put("adopted", Arrays.asList("from orphanage by CodeSource path"));
                    put("used", Arrays.asList(" to library usage for lib "));
                }
            };
    public static final ShredEntryClassifier ENTRY_CLASSIFIER =
            new ShredEntryClassifier(PATTERN_SIGNATURES);

    public static final List<String> EXTRACTED_VAL_NAMES =
            Arrays.asList("fqcn", "location", "application");
    public static final Map<String, Pattern> VALUE_EXTRACTORS =
            new HashMap<String, Pattern>() {
                {
                    put(
                            "noput",
                            Pattern.compile(
                                    "\\- Not putting (?<fqcn>\\S+) in orphanage as its from"
                                            + " (?<location>~NOLOC~)?(?<application>~NOAPP~)?"));
                    put(
                            "noapp",
                            Pattern.compile(
                                    "\\- Couldn't find app for (?<fqcn>\\S+) with CodeSource path"
                                            + " (?<application>~NOAPP~)?(?<location>.*)$"));
                    put(
                            "orphan",
                            Pattern.compile(
                                    "\\- Adding (?<fqcn>\\S+) to"
                                        + " orphanage(?<location>~NOLOC~)?(?<application>~NOAPP~)?$"));
                    put(
                            "uninventoried",
                            Pattern.compile(
                                    "\\- Adding (?<fqcn>\\S+) to list of missed classload events"
                                            + " for uninventoried"
                                            + " (?<location>~NOLOC~)?(?<application>.*)$"));
                    put(
                            "contains",
                            Pattern.compile(
                                    "\\- url \\@detectLibraryClass (?<location>.+) contains"
                                            + " (?<fqcn>\\S+) for app \".+\""
                                            + " \\((?<application>.*)\\)$"));
                    put(
                            "nolib",
                            Pattern.compile(
                                    "\\- No library found for \\S+ in app \".+\""
                                        + " (?<location>~NOLOC~)?(?<fqcn>~NOCLASS~)?\\((?<application>.*)\\)$"));
                    put(
                            "adopted",
                            Pattern.compile(
                                    "\\- Took (?<fqcn>\\S+) from orphanage by CodeSource path"
                                            + " (?<location>.+) and passing to app"
                                            + " \"(?<application>.*)\"$"));
                    put(
                            "used",
                            Pattern.compile(
                                    "\\- Adding (?<fqcn>\\S+) to library usage for lib"
                                            + " (?<jarname>\\S+) in app (?<location>~NOLOC~)?\".+\""
                                            + " \\((?<application>.*)\\)$"));
                    put(Shred.DEFAULT_TYPE, Pattern.compile("^~NOMATCH~$"));
                }
            };
    public static final ShredValueExtractor VALUE_EXTRACTOR =
            new ShredValueExtractor(EXTRACTED_VAL_NAMES, VALUE_EXTRACTORS);

    // Shred misfits table "acel_misfits"
    public static final String MISFITS_TBL_NAME = "acel_misfits";
    public static final String MISFITS_TBL_CREATE_SQL =
            "create table acel_misfits(" + "line integer primary key references log(line))";
    public static final List<String> MISFITS_TBL_INDEX_SQLS = List.of();
    public static final List<String> MISFITS_TBL_COLUMNS = Arrays.asList("line");
}
