/* (C)2024 */
package com.contrastsecurity.agent.loghog.shred;

import static com.contrastsecurity.agent.loghog.db.EmbeddedDatabaseFactory.jooq;

import com.contrastsecurity.agent.loghog.sql.BaseCreatableSqlTable;
import java.util.List;
import org.jooq.CreateTableElementListStep;

public class ShredSqlTable extends BaseCreatableSqlTable {

  public ShredSqlTable(
      final String name,
      final List<ShredRowMetaData> shredMetadata,
      final String keyColumnName,
      final List<String> createContraintsSql,
      final List<String> createIndicesSql) {
    super(
        name,
        columnNames(shredMetadata),
        createSql(name, keyColumnName, shredMetadata),
        createContraintsSql,
        createIndicesSql,
        insertRowSql(name, shredMetadata));
  }

  public static List<String> columnNames(final List<ShredRowMetaData> shredMetadata) {
    return shredMetadata.stream().map(colMeta -> colMeta.columnName()).toList();
  }

  public static List<Class> columnTypes(final List<ShredRowMetaData> shredMetadata) {
    return shredMetadata.stream().map(colMeta -> colMeta.javaType()).toList();
  }

  protected static String createSql(
      final String name, final String keyColumnName, final List<ShredRowMetaData> shredMetadata) {
    CreateTableElementListStep step = jooq().createTable(name).primaryKey(keyColumnName);
    for (ShredRowMetaData metaData : shredMetadata) {
      step = step.column(metaData.columnName(), metaData.jooqDataType());
    }
    return step.getSQL();
  }

  // TODO can we jOOQ this?
  protected static String insertRowSql(
      final String name, final List<ShredRowMetaData> shredMetadata) {
    final List<String> columnNames = columnNames(shredMetadata);
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
