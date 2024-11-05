/*
 * This file is generated by jOOQ.
 */
package org.jooq.generated.information_schema.tables;


import java.util.Collection;

import org.jooq.Condition;
import org.jooq.Field;
import org.jooq.Name;
import org.jooq.PlainSQL;
import org.jooq.QueryPart;
import org.jooq.SQL;
import org.jooq.Schema;
import org.jooq.Select;
import org.jooq.Stringly;
import org.jooq.Table;
import org.jooq.TableField;
import org.jooq.TableOptions;
import org.jooq.generated.information_schema.InformationSchema;
import org.jooq.generated.information_schema.tables.records.ConstantsRecord;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;
import org.jooq.impl.TableImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class Constants extends TableImpl<ConstantsRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * The reference instance of <code>INFORMATION_SCHEMA.CONSTANTS</code>
     */
    public static final Constants CONSTANTS = new Constants();

    /**
     * The class holding records for this type
     */
    @Override
    public Class<ConstantsRecord> getRecordType() {
        return ConstantsRecord.class;
    }

    /**
     * The column <code>INFORMATION_SCHEMA.CONSTANTS.CONSTANT_CATALOG</code>.
     */
    public final TableField<ConstantsRecord, String> CONSTANT_CATALOG = createField(DSL.name("CONSTANT_CATALOG"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.CONSTANTS.CONSTANT_SCHEMA</code>.
     */
    public final TableField<ConstantsRecord, String> CONSTANT_SCHEMA = createField(DSL.name("CONSTANT_SCHEMA"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.CONSTANTS.CONSTANT_NAME</code>.
     */
    public final TableField<ConstantsRecord, String> CONSTANT_NAME = createField(DSL.name("CONSTANT_NAME"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.CONSTANTS.VALUE_DEFINITION</code>.
     */
    public final TableField<ConstantsRecord, String> VALUE_DEFINITION = createField(DSL.name("VALUE_DEFINITION"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.CONSTANTS.DATA_TYPE</code>.
     */
    public final TableField<ConstantsRecord, String> DATA_TYPE = createField(DSL.name("DATA_TYPE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.CONSTANTS.CHARACTER_MAXIMUM_LENGTH</code>.
     */
    public final TableField<ConstantsRecord, Long> CHARACTER_MAXIMUM_LENGTH = createField(DSL.name("CHARACTER_MAXIMUM_LENGTH"), SQLDataType.BIGINT, this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.CONSTANTS.CHARACTER_OCTET_LENGTH</code>.
     */
    public final TableField<ConstantsRecord, Long> CHARACTER_OCTET_LENGTH = createField(DSL.name("CHARACTER_OCTET_LENGTH"), SQLDataType.BIGINT, this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.CONSTANTS.CHARACTER_SET_CATALOG</code>.
     */
    public final TableField<ConstantsRecord, String> CHARACTER_SET_CATALOG = createField(DSL.name("CHARACTER_SET_CATALOG"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.CONSTANTS.CHARACTER_SET_SCHEMA</code>.
     */
    public final TableField<ConstantsRecord, String> CHARACTER_SET_SCHEMA = createField(DSL.name("CHARACTER_SET_SCHEMA"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.CONSTANTS.CHARACTER_SET_NAME</code>.
     */
    public final TableField<ConstantsRecord, String> CHARACTER_SET_NAME = createField(DSL.name("CHARACTER_SET_NAME"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.CONSTANTS.COLLATION_CATALOG</code>.
     */
    public final TableField<ConstantsRecord, String> COLLATION_CATALOG = createField(DSL.name("COLLATION_CATALOG"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.CONSTANTS.COLLATION_SCHEMA</code>.
     */
    public final TableField<ConstantsRecord, String> COLLATION_SCHEMA = createField(DSL.name("COLLATION_SCHEMA"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.CONSTANTS.COLLATION_NAME</code>.
     */
    public final TableField<ConstantsRecord, String> COLLATION_NAME = createField(DSL.name("COLLATION_NAME"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.CONSTANTS.NUMERIC_PRECISION</code>.
     */
    public final TableField<ConstantsRecord, Integer> NUMERIC_PRECISION = createField(DSL.name("NUMERIC_PRECISION"), SQLDataType.INTEGER, this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.CONSTANTS.NUMERIC_PRECISION_RADIX</code>.
     */
    public final TableField<ConstantsRecord, Integer> NUMERIC_PRECISION_RADIX = createField(DSL.name("NUMERIC_PRECISION_RADIX"), SQLDataType.INTEGER, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.CONSTANTS.NUMERIC_SCALE</code>.
     */
    public final TableField<ConstantsRecord, Integer> NUMERIC_SCALE = createField(DSL.name("NUMERIC_SCALE"), SQLDataType.INTEGER, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.CONSTANTS.DATETIME_PRECISION</code>.
     */
    public final TableField<ConstantsRecord, Integer> DATETIME_PRECISION = createField(DSL.name("DATETIME_PRECISION"), SQLDataType.INTEGER, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.CONSTANTS.INTERVAL_TYPE</code>.
     */
    public final TableField<ConstantsRecord, String> INTERVAL_TYPE = createField(DSL.name("INTERVAL_TYPE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.CONSTANTS.INTERVAL_PRECISION</code>.
     */
    public final TableField<ConstantsRecord, Integer> INTERVAL_PRECISION = createField(DSL.name("INTERVAL_PRECISION"), SQLDataType.INTEGER, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.CONSTANTS.MAXIMUM_CARDINALITY</code>.
     */
    public final TableField<ConstantsRecord, Integer> MAXIMUM_CARDINALITY = createField(DSL.name("MAXIMUM_CARDINALITY"), SQLDataType.INTEGER, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.CONSTANTS.DTD_IDENTIFIER</code>.
     */
    public final TableField<ConstantsRecord, String> DTD_IDENTIFIER = createField(DSL.name("DTD_IDENTIFIER"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.CONSTANTS.DECLARED_DATA_TYPE</code>.
     */
    public final TableField<ConstantsRecord, String> DECLARED_DATA_TYPE = createField(DSL.name("DECLARED_DATA_TYPE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.CONSTANTS.DECLARED_NUMERIC_PRECISION</code>.
     */
    public final TableField<ConstantsRecord, Integer> DECLARED_NUMERIC_PRECISION = createField(DSL.name("DECLARED_NUMERIC_PRECISION"), SQLDataType.INTEGER, this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.CONSTANTS.DECLARED_NUMERIC_SCALE</code>.
     */
    public final TableField<ConstantsRecord, Integer> DECLARED_NUMERIC_SCALE = createField(DSL.name("DECLARED_NUMERIC_SCALE"), SQLDataType.INTEGER, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.CONSTANTS.GEOMETRY_TYPE</code>.
     */
    public final TableField<ConstantsRecord, String> GEOMETRY_TYPE = createField(DSL.name("GEOMETRY_TYPE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.CONSTANTS.GEOMETRY_SRID</code>.
     */
    public final TableField<ConstantsRecord, Integer> GEOMETRY_SRID = createField(DSL.name("GEOMETRY_SRID"), SQLDataType.INTEGER, this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.CONSTANTS.REMARKS</code>.
     */
    public final TableField<ConstantsRecord, String> REMARKS = createField(DSL.name("REMARKS"), SQLDataType.VARCHAR(1000000000), this, "");

    private Constants(Name alias, Table<ConstantsRecord> aliased) {
        this(alias, aliased, (Field<?>[]) null, null);
    }

    private Constants(Name alias, Table<ConstantsRecord> aliased, Field<?>[] parameters, Condition where) {
        super(alias, null, aliased, parameters, DSL.comment(""), TableOptions.table(), where);
    }

    /**
     * Create an aliased <code>INFORMATION_SCHEMA.CONSTANTS</code> table
     * reference
     */
    public Constants(String alias) {
        this(DSL.name(alias), CONSTANTS);
    }

    /**
     * Create an aliased <code>INFORMATION_SCHEMA.CONSTANTS</code> table
     * reference
     */
    public Constants(Name alias) {
        this(alias, CONSTANTS);
    }

    /**
     * Create a <code>INFORMATION_SCHEMA.CONSTANTS</code> table reference
     */
    public Constants() {
        this(DSL.name("CONSTANTS"), null);
    }

    @Override
    public Schema getSchema() {
        return aliased() ? null : InformationSchema.INFORMATION_SCHEMA;
    }

    @Override
    public Constants as(String alias) {
        return new Constants(DSL.name(alias), this);
    }

    @Override
    public Constants as(Name alias) {
        return new Constants(alias, this);
    }

    @Override
    public Constants as(Table<?> alias) {
        return new Constants(alias.getQualifiedName(), this);
    }

    /**
     * Rename this table
     */
    @Override
    public Constants rename(String name) {
        return new Constants(DSL.name(name), null);
    }

    /**
     * Rename this table
     */
    @Override
    public Constants rename(Name name) {
        return new Constants(name, null);
    }

    /**
     * Rename this table
     */
    @Override
    public Constants rename(Table<?> name) {
        return new Constants(name.getQualifiedName(), null);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Constants where(Condition condition) {
        return new Constants(getQualifiedName(), aliased() ? this : null, null, condition);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Constants where(Collection<? extends Condition> conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Constants where(Condition... conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Constants where(Field<Boolean> condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Constants where(SQL condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Constants where(@Stringly.SQL String condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Constants where(@Stringly.SQL String condition, Object... binds) {
        return where(DSL.condition(condition, binds));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Constants where(@Stringly.SQL String condition, QueryPart... parts) {
        return where(DSL.condition(condition, parts));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Constants whereExists(Select<?> select) {
        return where(DSL.exists(select));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Constants whereNotExists(Select<?> select) {
        return where(DSL.notExists(select));
    }
}
