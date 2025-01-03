/*
 * This file is generated by jOOQ.
 */
package com.contrtastsecurity.agent.loghog.jooq.information_schema.tables;


import com.contrtastsecurity.agent.loghog.jooq.information_schema.InformationSchema;
import com.contrtastsecurity.agent.loghog.jooq.information_schema.tables.records.ViewsRecord;

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
public class Views extends TableImpl<ViewsRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * The reference instance of <code>INFORMATION_SCHEMA.VIEWS</code>
     */
    public static final Views VIEWS = new Views();

    /**
     * The class holding records for this type
     */
    @Override
    public Class<ViewsRecord> getRecordType() {
        return ViewsRecord.class;
    }

    /**
     * The column <code>INFORMATION_SCHEMA.VIEWS.TABLE_CATALOG</code>.
     */
    public final TableField<ViewsRecord, String> TABLE_CATALOG = createField(DSL.name("TABLE_CATALOG"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.VIEWS.TABLE_SCHEMA</code>.
     */
    public final TableField<ViewsRecord, String> TABLE_SCHEMA = createField(DSL.name("TABLE_SCHEMA"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.VIEWS.TABLE_NAME</code>.
     */
    public final TableField<ViewsRecord, String> TABLE_NAME = createField(DSL.name("TABLE_NAME"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.VIEWS.VIEW_DEFINITION</code>.
     */
    public final TableField<ViewsRecord, String> VIEW_DEFINITION = createField(DSL.name("VIEW_DEFINITION"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.VIEWS.CHECK_OPTION</code>.
     */
    public final TableField<ViewsRecord, String> CHECK_OPTION = createField(DSL.name("CHECK_OPTION"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.VIEWS.IS_UPDATABLE</code>.
     */
    public final TableField<ViewsRecord, String> IS_UPDATABLE = createField(DSL.name("IS_UPDATABLE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.VIEWS.INSERTABLE_INTO</code>.
     */
    public final TableField<ViewsRecord, String> INSERTABLE_INTO = createField(DSL.name("INSERTABLE_INTO"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.VIEWS.IS_TRIGGER_UPDATABLE</code>.
     */
    public final TableField<ViewsRecord, String> IS_TRIGGER_UPDATABLE = createField(DSL.name("IS_TRIGGER_UPDATABLE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.VIEWS.IS_TRIGGER_DELETABLE</code>.
     */
    public final TableField<ViewsRecord, String> IS_TRIGGER_DELETABLE = createField(DSL.name("IS_TRIGGER_DELETABLE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.VIEWS.IS_TRIGGER_INSERTABLE_INTO</code>.
     */
    public final TableField<ViewsRecord, String> IS_TRIGGER_INSERTABLE_INTO = createField(DSL.name("IS_TRIGGER_INSERTABLE_INTO"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.VIEWS.STATUS</code>.
     */
    public final TableField<ViewsRecord, String> STATUS = createField(DSL.name("STATUS"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.VIEWS.REMARKS</code>.
     */
    public final TableField<ViewsRecord, String> REMARKS = createField(DSL.name("REMARKS"), SQLDataType.VARCHAR(1000000000), this, "");

    private Views(Name alias, Table<ViewsRecord> aliased) {
        this(alias, aliased, (Field<?>[]) null, null);
    }

    private Views(Name alias, Table<ViewsRecord> aliased, Field<?>[] parameters, Condition where) {
        super(alias, null, aliased, parameters, DSL.comment(""), TableOptions.view(), where);
    }

    /**
     * Create an aliased <code>INFORMATION_SCHEMA.VIEWS</code> table reference
     */
    public Views(String alias) {
        this(DSL.name(alias), VIEWS);
    }

    /**
     * Create an aliased <code>INFORMATION_SCHEMA.VIEWS</code> table reference
     */
    public Views(Name alias) {
        this(alias, VIEWS);
    }

    /**
     * Create a <code>INFORMATION_SCHEMA.VIEWS</code> table reference
     */
    public Views() {
        this(DSL.name("VIEWS"), null);
    }

    @Override
    public Schema getSchema() {
        return aliased() ? null : InformationSchema.INFORMATION_SCHEMA;
    }

    @Override
    public Views as(String alias) {
        return new Views(DSL.name(alias), this);
    }

    @Override
    public Views as(Name alias) {
        return new Views(alias, this);
    }

    @Override
    public Views as(Table<?> alias) {
        return new Views(alias.getQualifiedName(), this);
    }

    /**
     * Rename this table
     */
    @Override
    public Views rename(String name) {
        return new Views(DSL.name(name), null);
    }

    /**
     * Rename this table
     */
    @Override
    public Views rename(Name name) {
        return new Views(name, null);
    }

    /**
     * Rename this table
     */
    @Override
    public Views rename(Table<?> name) {
        return new Views(name.getQualifiedName(), null);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Views where(Condition condition) {
        return new Views(getQualifiedName(), aliased() ? this : null, null, condition);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Views where(Collection<? extends Condition> conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Views where(Condition... conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Views where(Field<Boolean> condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Views where(SQL condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Views where(@Stringly.SQL String condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Views where(@Stringly.SQL String condition, Object... binds) {
        return where(DSL.condition(condition, binds));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Views where(@Stringly.SQL String condition, QueryPart... parts) {
        return where(DSL.condition(condition, parts));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Views whereExists(Select<?> select) {
        return where(DSL.exists(select));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Views whereNotExists(Select<?> select) {
        return where(DSL.notExists(select));
    }
}
