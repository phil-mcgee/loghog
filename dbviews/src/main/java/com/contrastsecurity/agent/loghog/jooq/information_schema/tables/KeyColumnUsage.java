/*
 * This file is generated by jOOQ.
 */
package com.contrtastsecurity.agent.loghog.jooq.information_schema.tables;


import com.contrtastsecurity.agent.loghog.jooq.information_schema.InformationSchema;
import com.contrtastsecurity.agent.loghog.jooq.information_schema.tables.records.KeyColumnUsageRecord;

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
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;
import org.jooq.impl.TableImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class KeyColumnUsage extends TableImpl<KeyColumnUsageRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * The reference instance of
     * <code>INFORMATION_SCHEMA.KEY_COLUMN_USAGE</code>
     */
    public static final KeyColumnUsage KEY_COLUMN_USAGE = new KeyColumnUsage();

    /**
     * The class holding records for this type
     */
    @Override
    public Class<KeyColumnUsageRecord> getRecordType() {
        return KeyColumnUsageRecord.class;
    }

    /**
     * The column
     * <code>INFORMATION_SCHEMA.KEY_COLUMN_USAGE.CONSTRAINT_CATALOG</code>.
     */
    public final TableField<KeyColumnUsageRecord, String> CONSTRAINT_CATALOG = createField(DSL.name("CONSTRAINT_CATALOG"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.KEY_COLUMN_USAGE.CONSTRAINT_SCHEMA</code>.
     */
    public final TableField<KeyColumnUsageRecord, String> CONSTRAINT_SCHEMA = createField(DSL.name("CONSTRAINT_SCHEMA"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.KEY_COLUMN_USAGE.CONSTRAINT_NAME</code>.
     */
    public final TableField<KeyColumnUsageRecord, String> CONSTRAINT_NAME = createField(DSL.name("CONSTRAINT_NAME"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.KEY_COLUMN_USAGE.TABLE_CATALOG</code>.
     */
    public final TableField<KeyColumnUsageRecord, String> TABLE_CATALOG = createField(DSL.name("TABLE_CATALOG"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.KEY_COLUMN_USAGE.TABLE_SCHEMA</code>.
     */
    public final TableField<KeyColumnUsageRecord, String> TABLE_SCHEMA = createField(DSL.name("TABLE_SCHEMA"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.KEY_COLUMN_USAGE.TABLE_NAME</code>.
     */
    public final TableField<KeyColumnUsageRecord, String> TABLE_NAME = createField(DSL.name("TABLE_NAME"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.KEY_COLUMN_USAGE.COLUMN_NAME</code>.
     */
    public final TableField<KeyColumnUsageRecord, String> COLUMN_NAME = createField(DSL.name("COLUMN_NAME"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.KEY_COLUMN_USAGE.ORDINAL_POSITION</code>.
     */
    public final TableField<KeyColumnUsageRecord, Integer> ORDINAL_POSITION = createField(DSL.name("ORDINAL_POSITION"), SQLDataType.INTEGER, this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.KEY_COLUMN_USAGE.POSITION_IN_UNIQUE_CONSTRAINT</code>.
     */
    public final TableField<KeyColumnUsageRecord, Integer> POSITION_IN_UNIQUE_CONSTRAINT = createField(DSL.name("POSITION_IN_UNIQUE_CONSTRAINT"), SQLDataType.INTEGER, this, "");

    private KeyColumnUsage(Name alias, Table<KeyColumnUsageRecord> aliased) {
        this(alias, aliased, (Field<?>[]) null, null);
    }

    private KeyColumnUsage(Name alias, Table<KeyColumnUsageRecord> aliased, Field<?>[] parameters, Condition where) {
        super(alias, null, aliased, parameters, DSL.comment(""), TableOptions.view(), where);
    }

    /**
     * Create an aliased <code>INFORMATION_SCHEMA.KEY_COLUMN_USAGE</code> table
     * reference
     */
    public KeyColumnUsage(String alias) {
        this(DSL.name(alias), KEY_COLUMN_USAGE);
    }

    /**
     * Create an aliased <code>INFORMATION_SCHEMA.KEY_COLUMN_USAGE</code> table
     * reference
     */
    public KeyColumnUsage(Name alias) {
        this(alias, KEY_COLUMN_USAGE);
    }

    /**
     * Create a <code>INFORMATION_SCHEMA.KEY_COLUMN_USAGE</code> table reference
     */
    public KeyColumnUsage() {
        this(DSL.name("KEY_COLUMN_USAGE"), null);
    }

    @Override
    public Schema getSchema() {
        return aliased() ? null : InformationSchema.INFORMATION_SCHEMA;
    }

    @Override
    public KeyColumnUsage as(String alias) {
        return new KeyColumnUsage(DSL.name(alias), this);
    }

    @Override
    public KeyColumnUsage as(Name alias) {
        return new KeyColumnUsage(alias, this);
    }

    @Override
    public KeyColumnUsage as(Table<?> alias) {
        return new KeyColumnUsage(alias.getQualifiedName(), this);
    }

    /**
     * Rename this table
     */
    @Override
    public KeyColumnUsage rename(String name) {
        return new KeyColumnUsage(DSL.name(name), null);
    }

    /**
     * Rename this table
     */
    @Override
    public KeyColumnUsage rename(Name name) {
        return new KeyColumnUsage(name, null);
    }

    /**
     * Rename this table
     */
    @Override
    public KeyColumnUsage rename(Table<?> name) {
        return new KeyColumnUsage(name.getQualifiedName(), null);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public KeyColumnUsage where(Condition condition) {
        return new KeyColumnUsage(getQualifiedName(), aliased() ? this : null, null, condition);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public KeyColumnUsage where(Collection<? extends Condition> conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public KeyColumnUsage where(Condition... conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public KeyColumnUsage where(Field<Boolean> condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public KeyColumnUsage where(SQL condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public KeyColumnUsage where(@Stringly.SQL String condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public KeyColumnUsage where(@Stringly.SQL String condition, Object... binds) {
        return where(DSL.condition(condition, binds));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public KeyColumnUsage where(@Stringly.SQL String condition, QueryPart... parts) {
        return where(DSL.condition(condition, parts));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public KeyColumnUsage whereExists(Select<?> select) {
        return where(DSL.exists(select));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public KeyColumnUsage whereNotExists(Select<?> select) {
        return where(DSL.notExists(select));
    }
}