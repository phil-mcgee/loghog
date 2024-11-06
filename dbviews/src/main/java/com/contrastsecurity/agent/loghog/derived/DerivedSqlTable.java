package com.contrastsecurity.agent.loghog.derived;

import com.contrastsecurity.agent.loghog.sql.BaseCreatableSqlTable;
import org.jooq.CreateTableElementListStep;

import java.util.List;

import static com.contrastsecurity.agent.loghog.db.EmbeddedDatabaseFactory.jooq;

public class DerivedSqlTable extends BaseCreatableSqlTable {

    public DerivedSqlTable(
            final String name,
            final List<DerivedRowMetaData> derivedMetadata,
            final String keyColumnName,
            final List<String> createContraintsSql,
            final List<String> createIndicesSql) {
        super(
                name,
                columnNames(derivedMetadata),
                createSql(name, keyColumnName, derivedMetadata),
                createContraintsSql,
                createIndicesSql,
                insertRowSql(name, derivedMetadata));
    }


    public static List<String> columnNames(final List<DerivedRowMetaData> derivedMetadata) {
        return derivedMetadata.stream().map(colMeta -> colMeta.columnName()).toList();
    }

    public static List<Class> columnTypes(final List<DerivedRowMetaData> derivedMetadata) {
        return derivedMetadata.stream().map(colMeta -> colMeta.javaType()).toList();
    }

    protected static String createSql(
            final String name, final String keyColumnName, final List<DerivedRowMetaData> derivedMetadata) {
        CreateTableElementListStep step = jooq().createTable(name).primaryKey(keyColumnName);
        for (DerivedRowMetaData metaData : derivedMetadata) {
            step = step.column(metaData.columnName(), metaData.jooqDataType());
        }
        return step.getSQL();
    }

    // TODO can we jOOQ this?
    protected static String insertRowSql(
            final String name, final List<DerivedRowMetaData> derivedMetadata) {
        final List<String> columnNames = columnNames(derivedMetadata);
        final StringBuilder sb = new StringBuilder("insert into ");
        sb.append("\"").append(name).append("\"").append(" (");
        String delimiter = "";
        for (final String insertColumnName : columnNames) {
            sb.append(delimiter).append("\"").append(insertColumnName).append("\"");
            delimiter = ", ";
        }
        sb.append(") values (");
        delimiter = "";
        for (final String dontCare : columnNames) {
            sb.append(delimiter).append("?");
            delimiter = ", ";
        }
        return sb.append(")").toString();
    }

}

