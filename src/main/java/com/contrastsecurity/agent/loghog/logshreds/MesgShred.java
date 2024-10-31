/* (C)2024 */
package com.contrastsecurity.agent.loghog.logshreds;

import static com.contrastsecurity.agent.loghog.db.LogDatabaseUtil.LOG_TABLE_NAME;
import static com.contrastsecurity.agent.loghog.shred.PatternGroup.*;
import static com.contrastsecurity.agent.loghog.shred.RowClassifier.ANY_PATTERN;

import com.contrastsecurity.agent.loghog.shred.AbstractShred;
import com.contrastsecurity.agent.loghog.shred.PatternRowValuesExtractor;
import com.contrastsecurity.agent.loghog.shred.RowClassifier;
import com.contrastsecurity.agent.loghog.shred.RowValuesExtractor;
import com.contrastsecurity.agent.loghog.shred.ShredSource;
import com.contrastsecurity.agent.loghog.shred.ShredSqlTable;
import com.contrastsecurity.agent.loghog.sql.SqlTableBase;

import java.time.LocalDateTime;
import java.util.*;
import java.util.regex.Pattern;

import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;

public class MesgShred extends AbstractShred {

    static final String SHRED_TABLE_NAME = "mesg";
    static final String SHRED_KEY_COLUMN = "line";

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

    static final String MISFITS_TABLE_NAME = "cont";
    static final String MISFITS_KEY_COLUMN = "line";

    static final List<ShredRowMetaData> MISFITS_METADATA = List.of(
        new ShredRowMetaData("line",
                SQLDataType.INTEGER.notNull(), Integer.class, LOG_TABLE_LINE_COL),
        new ShredRowMetaData("mesg",
                SQLDataType.INTEGER, Integer.class, LAST_MATCH_KEY)
    );

    static final ShredSqlTable SHRED_SQL_TABLE = new ShredSqlTable(
            SHRED_TABLE_NAME,
            SHRED_METADATA,
            SHRED_KEY_COLUMN,
            shredConstraintsCreateSql(),
            shredIndicesCreateSql());

    static final ShredSqlTable MISFITS_SQL_TABLE = new ShredSqlTable(
            MISFITS_TABLE_NAME,
            MISFITS_METADATA,
            MISFITS_KEY_COLUMN,
            misfitsConstraintsCreateSql(),
            null);

    public static final RowValuesExtractor VALUE_EXTRACTOR =
            new PatternRowValuesExtractor(
                    new HashMap<String, Pattern>() {
                        {
                            put(ANY_PATTERN, Pattern.compile(FULL_PREAMBLE_XTRACT + "-( (?<message>.*))?$"));
                        }
                    },
                    Arrays.asList(TIMESTAMP_VAR, THREAD_VAR, LOGGER_VAR, LEVEL_VAR, "message"));

    public static final ShredSource SHRED_SOURCE = new ShredSource() {
        @Override
        public String sourceTableName() {
            return LOG_TABLE_NAME;
        }

        @Override
        public RowClassifier rowClassifier() {
            // classifies all rows as RowClassifier.ANY_PATTERN
            return new RowClassifier() {};
        }

        @Override
        public RowValuesExtractor rowValuesExtractor() {
            return VALUE_EXTRACTOR;
        }
    };

    public MesgShred() {
        super(SHRED_METADATA, SHRED_SQL_TABLE,MISFITS_METADATA, MISFITS_SQL_TABLE, SHRED_SOURCE);
    }

    static List<String> shredConstraintsCreateSql() {
        return List.of(
                DSL.alterTable(SHRED_TABLE_NAME).add(
                        DSL.constraint(SHRED_TABLE_NAME + "_FK_" + SHRED_KEY_COLUMN)
                                .foreignKey(SHRED_KEY_COLUMN)
                                .references(LOG_TABLE_NAME, "line")).getSQL());
    }

    static List<String> shredIndicesCreateSql() {
        return Arrays.asList(
                DSL.createIndex("idx_" + SHRED_TABLE_NAME + "_thread")
                        .on(SHRED_TABLE_NAME, "thread")
                        .getSQL());
    }

    static List<String> misfitsConstraintsCreateSql() {
        return List.of(
                DSL.alterTable(MISFITS_TABLE_NAME).add(
                        DSL.constraint(MISFITS_TABLE_NAME + "_FK_" + MISFITS_KEY_COLUMN)
                                .foreignKey(MISFITS_KEY_COLUMN)
                                .references(LOG_TABLE_NAME, "line")).getSQL(),
                DSL.alterTable(MISFITS_TABLE_NAME).add(
                        DSL.constraint(MISFITS_TABLE_NAME + "_FK_" + "mesg")
                                .foreignKey("mesg")
                                .references(SHRED_TABLE_NAME, "line")).getSQL());
    }
}
