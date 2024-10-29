/* (C)2024 */
package com.contrastsecurity.agent.loghog.shred;

import static com.contrastsecurity.agent.loghog.shred.PatternGroup.*;
import static com.contrastsecurity.agent.loghog.shred.ShredEntrySelector.ALL_ENTRIES_SIGNATURE;
import static com.contrastsecurity.agent.loghog.shred.ShredEntrySelector.ALL_ENTRIES_SQL;

import com.contrastsecurity.agent.loghog.sql.SqlTableBase;
import java.util.*;
import java.util.regex.Pattern;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;

public class MesgShred extends Shred {

    public MesgShred() {
        super(
                new SqlTableBase(
                        shredTableName(),
                        shredTableCreateSql(),
                        shredTableIndicesCreateSql(),
                        shredTableColumns()),
                new SqlTableBase(
                        misfitsTableName(),
                        misfitsTableCreateSql(),
                        misfitsTableIndicesCreateSql(),
                        misfitsTableColumns()),
                ENTRY_SELECTOR,
                ENTRY_CLASSIFIER,
                VALUE_EXTRACTOR);
    }

    public static String shredTableName() {
        return "mesg";
    }

    public static List<String> shredTableColumns() {
        return Arrays.asList("line", "timestamp", "thread", "logger", "level", "message");
    }

    public static String shredTableCreateSql() {
        return DSL.createTable(shredTableName())
                .column("line", SQLDataType.INTEGER.notNull())
                .primaryKey("line")
                .constraint(
                        DSL.constraint(shredTableName() + "_FK_line")
                                .foreignKey("line")
                                .references("log", "line"))
                .column("timestamp", SQLDataType.LOCALDATETIME(3).notNull())
                .column("thread", SQLDataType.VARCHAR.notNull())
                .column("logger", SQLDataType.VARCHAR.notNull())
                .column("level", SQLDataType.VARCHAR.notNull())
                .column("message", SQLDataType.VARCHAR)
                .getSQL();
    }

    public static List<String> shredTableIndicesCreateSql() {
        return Arrays.asList(
                DSL.createIndex("idx_" + shredTableName() + "_thread")
                        .on(shredTableName(), "thread")
                        .getSQL());
    }

    // Shred misfits table "cont" identifies "continuation" lines from log file that
    // don't include the normal timestamp, thread, class, log level preamble because they
    // are (probably) continuation lines from a preceding multi-line log message.
    // The mesg column indentifies the last properly formatted log message and likely
    // "parent" of the continuation line.

    public static String misfitsTableName() {
        return "cont";
    }

    public static List<String> misfitsTableColumns() {
        return Arrays.asList("line", "mesg");
    }

    public static String misfitsTableCreateSql() {
        return DSL.createTable(misfitsTableName())
                .column("line", SQLDataType.INTEGER.notNull())
                .primaryKey("line")
                .constraint(
                        DSL.constraint(misfitsTableName() + "_FK_line")
                                .foreignKey("line")
                                .references("log", "line"))
                .column("mesg", SQLDataType.INTEGER)
                .constraint(
                        DSL.constraint(misfitsTableName() + "_FK_mesg")
                                .foreignKey("mesg")
                                .references(shredTableName(), "line"))
                .getSQL();
    }

    public static List<String> misfitsTableIndicesCreateSql() {
        return Arrays.asList();
    }

    @Override
    public Object[] transformValues(
            int line, String entry, String type, Map<String, Object> extractedVals) {
        return new Object[] {
            line,
            extractedVals.get("timestamp").toString().replace(',', '.'),
            extractedVals.get("thread"),
            extractedVals.get("logger"),
            extractedVals.get("level"),
            extractedVals.get("message")
        };
    }

    @Override
    public Object[] transformMisfits(int line, int lastGoodLine) {
        return new Object[] {line, lastGoodLine == -1 ? null : lastGoodLine};
    }

    // Selects all lines from log table
    public static final ShredEntrySelector ENTRY_SELECTOR =
            new ShredEntrySelector(ALL_ENTRIES_SIGNATURE, ALL_ENTRIES_SQL, 1000);

    // Just one pattern type. Because we just have one pattern we don't really
    // need the classifier.  Misfit entries (continuation lines) are identified by the failure
    // of an entry to match our default pattern
    public static final ShredEntryClassifier ENTRY_CLASSIFIER = new ShredEntryClassifier();

    public static final List<String> EXTRACTED_VAL_NAMES =
            Arrays.asList(TIMESTAMP_VAR, THREAD_VAR, LOGGER_VAR, LEVEL_VAR, "message");
    public static final Map<String, Pattern> VALUE_EXTRACTORS =
            new HashMap<String, Pattern>() {
                {
                    put(
                            Shred.DEFAULT_TYPE,
                            Pattern.compile(FULL_PREAMBLE_XTRACT + "-( (?<message>.*))?$"));
                }
            };
    public static final ShredValueExtractor VALUE_EXTRACTOR =
            new ShredValueExtractor(EXTRACTED_VAL_NAMES, VALUE_EXTRACTORS);

    public static void main(String[] args) {
        System.out.println(misfitsTableCreateSql());
    }
}
