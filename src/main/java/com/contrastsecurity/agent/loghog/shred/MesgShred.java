/* (C)2024 */
package com.contrastsecurity.agent.loghog.shred;

import static com.contrastsecurity.agent.loghog.shred.PatternGroup.*;
import static com.contrastsecurity.agent.loghog.shred.RowClassifier.ANY_PATTERN;

import com.contrastsecurity.agent.loghog.db.LogDatabaseUtil;
import com.contrastsecurity.agent.loghog.sql.SqlTableBase;

import java.time.LocalDateTime;
import java.util.*;
import java.util.regex.Pattern;

import org.jooq.CreateTableElementListStep;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;

public class MesgShred extends AbstractShred {

    static final List<ShredRowMetaData> SHRED_METADATA = List.of(
            new ShredRowMetaData("line",
                    SQLDataType.INTEGER.notNull(), Integer.class, LOG_TABLE_LINE_COL),
            new ShredRowMetaData("timestamp",
                    SQLDataType.LOCALDATETIME(3).notNull(), LocalDateTime.class, TIMESTAMP_VAR),
            new ShredRowMetaData("thread",
                    SQLDataType.VARCHAR.notNull(), String.class, THREAD_VAR),
            new ShredRowMetaData("logger",
                    SQLDataType.VARCHAR.notNull(), String.class, LOGGER_VAR),
            new ShredRowMetaData("level",
                    SQLDataType.VARCHAR.notNull(), String.class, LEVEL_VAR),
            new ShredRowMetaData("message",
                    SQLDataType.VARCHAR, String.class, "message")
    );

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
                        null,
                        misfitsTableColumns()),
                new ShredSource() {
                    @Override
                    public String sourceTableName() {
                        return LogDatabaseUtil.LOG_TABLE_NAME;
                    }

                    @Override
                    public RowClassifier rowClassifier() {
                        // classifies all rows as RowClassifier.ANY_PATTERN
                        return new RowClassifier() {};
                    }

                    @Override
                    public RowValuesExtractor rowValuesExtractor() {
                        return null;
                    }
                });
    }

    public static String shredTableName() {
        return "mesg";
    }

    public static List<String> shredTableColumns() {
        return SHRED_METADATA.stream().map(rowMeta -> rowMeta.columnName()).toList();
    }

    public static String shredTableCreateSql() {
        CreateTableElementListStep step = DSL.createTable(shredTableName())
                .primaryKey("line");
        for (ShredRowMetaData metaData : SHRED_METADATA) {
            step = step.column(metaData.columnName(), metaData.jooqDataType());
        }
        return step.getSQL();
    }
//                .constraint(
//            DSL.constraint(shredTableName() + "_FK_line")
//            .foreignKey("line")
//                                .references(LogDatabaseUtil.LOG_TABLE_NAME, "line"))

    public static List<String> shredTableIndicesCreateSql() {
        return Arrays.asList(
                DSL.createIndex("idx_" + shredTableName() + "_thread")
                        .on(shredTableName(), "thread")
                        .getSQL());
    }

    // AbstractShred misfits table "cont" identifies "continuation" lines from log file that
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
                                .references(LogDatabaseUtil.LOG_TABLE_NAME, "line"))
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
    public Object[] shredRowValues (final Object[] sourceRow, final String patternId, final Map<String, Object> extractedVals) {
        Object[] shredRow = new Object[SHRED_METADATA.size()];
        int idx = 0;
        for (ShredRowMetaData metaData : SHRED_METADATA) {
            Object val = null;
            if (extractedVals.containsKey(metaData.extractName())) {
                val = extractedVals.get(metaData.extractName());
            } else if (LOG_TABLE_LINE_COL.equals(metaData.extractName())) {
                val = sourceRow[LOG_TABLE_LINE_IDX];
            }
            if (TIMESTAMP_VAR.equals(metaData.extractName())) {
                val = String.valueOf(val).replace(',', '.');
            }
            shredRow[idx++] = val;
        }
        final Object line = sourceRow[0];
        return shredRow;
    }

    @Override
    public Object[] misfitsRowValues(Object[] sourceRow, Object lastGoodLine) {
        final Object line = sourceRow[0];
        return new Object[] {line, lastGoodLine};
    }

     public static final List<String> EXTRACTED_VAL_NAMES =
            Arrays.asList(TIMESTAMP_VAR, THREAD_VAR, LOGGER_VAR, LEVEL_VAR, "message");
    public static final Map<String, Pattern> VALUE_EXTRACTORS =
            new HashMap<String, Pattern>() {
                {
                    put(ANY_PATTERN, Pattern.compile(FULL_PREAMBLE_XTRACT + "-( (?<message>.*))?$"));
                }
            };
    public static final RowValuesExtractor VALUE_EXTRACTOR =
            new PatternRowValuesExtractor(VALUE_EXTRACTORS, EXTRACTED_VAL_NAMES);
}
