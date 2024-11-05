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
import org.jooq.generated.information_schema.tables.records.InDoubtRecord;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;
import org.jooq.impl.TableImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class InDoubt extends TableImpl<InDoubtRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * The reference instance of <code>INFORMATION_SCHEMA.IN_DOUBT</code>
     */
    public static final InDoubt IN_DOUBT = new InDoubt();

    /**
     * The class holding records for this type
     */
    @Override
    public Class<InDoubtRecord> getRecordType() {
        return InDoubtRecord.class;
    }

    /**
     * The column <code>INFORMATION_SCHEMA.IN_DOUBT.TRANSACTION_NAME</code>.
     */
    public final TableField<InDoubtRecord, String> TRANSACTION_NAME = createField(DSL.name("TRANSACTION_NAME"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.IN_DOUBT.TRANSACTION_STATE</code>.
     */
    public final TableField<InDoubtRecord, String> TRANSACTION_STATE = createField(DSL.name("TRANSACTION_STATE"), SQLDataType.VARCHAR(1000000000), this, "");

    private InDoubt(Name alias, Table<InDoubtRecord> aliased) {
        this(alias, aliased, (Field<?>[]) null, null);
    }

    private InDoubt(Name alias, Table<InDoubtRecord> aliased, Field<?>[] parameters, Condition where) {
        super(alias, null, aliased, parameters, DSL.comment(""), TableOptions.table(), where);
    }

    /**
     * Create an aliased <code>INFORMATION_SCHEMA.IN_DOUBT</code> table
     * reference
     */
    public InDoubt(String alias) {
        this(DSL.name(alias), IN_DOUBT);
    }

    /**
     * Create an aliased <code>INFORMATION_SCHEMA.IN_DOUBT</code> table
     * reference
     */
    public InDoubt(Name alias) {
        this(alias, IN_DOUBT);
    }

    /**
     * Create a <code>INFORMATION_SCHEMA.IN_DOUBT</code> table reference
     */
    public InDoubt() {
        this(DSL.name("IN_DOUBT"), null);
    }

    @Override
    public Schema getSchema() {
        return aliased() ? null : InformationSchema.INFORMATION_SCHEMA;
    }

    @Override
    public InDoubt as(String alias) {
        return new InDoubt(DSL.name(alias), this);
    }

    @Override
    public InDoubt as(Name alias) {
        return new InDoubt(alias, this);
    }

    @Override
    public InDoubt as(Table<?> alias) {
        return new InDoubt(alias.getQualifiedName(), this);
    }

    /**
     * Rename this table
     */
    @Override
    public InDoubt rename(String name) {
        return new InDoubt(DSL.name(name), null);
    }

    /**
     * Rename this table
     */
    @Override
    public InDoubt rename(Name name) {
        return new InDoubt(name, null);
    }

    /**
     * Rename this table
     */
    @Override
    public InDoubt rename(Table<?> name) {
        return new InDoubt(name.getQualifiedName(), null);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public InDoubt where(Condition condition) {
        return new InDoubt(getQualifiedName(), aliased() ? this : null, null, condition);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public InDoubt where(Collection<? extends Condition> conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public InDoubt where(Condition... conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public InDoubt where(Field<Boolean> condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public InDoubt where(SQL condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public InDoubt where(@Stringly.SQL String condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public InDoubt where(@Stringly.SQL String condition, Object... binds) {
        return where(DSL.condition(condition, binds));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public InDoubt where(@Stringly.SQL String condition, QueryPart... parts) {
        return where(DSL.condition(condition, parts));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public InDoubt whereExists(Select<?> select) {
        return where(DSL.exists(select));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public InDoubt whereNotExists(Select<?> select) {
        return where(DSL.notExists(select));
    }
}
