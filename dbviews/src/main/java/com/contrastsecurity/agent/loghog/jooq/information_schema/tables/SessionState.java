/*
 * This file is generated by jOOQ.
 */
package com.contrtastsecurity.agent.loghog.jooq.information_schema.tables;


import com.contrtastsecurity.agent.loghog.jooq.information_schema.InformationSchema;
import com.contrtastsecurity.agent.loghog.jooq.information_schema.tables.records.SessionStateRecord;

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
public class SessionState extends TableImpl<SessionStateRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * The reference instance of <code>INFORMATION_SCHEMA.SESSION_STATE</code>
     */
    public static final SessionState SESSION_STATE = new SessionState();

    /**
     * The class holding records for this type
     */
    @Override
    public Class<SessionStateRecord> getRecordType() {
        return SessionStateRecord.class;
    }

    /**
     * The column <code>INFORMATION_SCHEMA.SESSION_STATE.STATE_KEY</code>.
     */
    public final TableField<SessionStateRecord, String> STATE_KEY = createField(DSL.name("STATE_KEY"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.SESSION_STATE.STATE_COMMAND</code>.
     */
    public final TableField<SessionStateRecord, String> STATE_COMMAND = createField(DSL.name("STATE_COMMAND"), SQLDataType.VARCHAR(1000000000), this, "");

    private SessionState(Name alias, Table<SessionStateRecord> aliased) {
        this(alias, aliased, (Field<?>[]) null, null);
    }

    private SessionState(Name alias, Table<SessionStateRecord> aliased, Field<?>[] parameters, Condition where) {
        super(alias, null, aliased, parameters, DSL.comment(""), TableOptions.table(), where);
    }

    /**
     * Create an aliased <code>INFORMATION_SCHEMA.SESSION_STATE</code> table
     * reference
     */
    public SessionState(String alias) {
        this(DSL.name(alias), SESSION_STATE);
    }

    /**
     * Create an aliased <code>INFORMATION_SCHEMA.SESSION_STATE</code> table
     * reference
     */
    public SessionState(Name alias) {
        this(alias, SESSION_STATE);
    }

    /**
     * Create a <code>INFORMATION_SCHEMA.SESSION_STATE</code> table reference
     */
    public SessionState() {
        this(DSL.name("SESSION_STATE"), null);
    }

    @Override
    public Schema getSchema() {
        return aliased() ? null : InformationSchema.INFORMATION_SCHEMA;
    }

    @Override
    public SessionState as(String alias) {
        return new SessionState(DSL.name(alias), this);
    }

    @Override
    public SessionState as(Name alias) {
        return new SessionState(alias, this);
    }

    @Override
    public SessionState as(Table<?> alias) {
        return new SessionState(alias.getQualifiedName(), this);
    }

    /**
     * Rename this table
     */
    @Override
    public SessionState rename(String name) {
        return new SessionState(DSL.name(name), null);
    }

    /**
     * Rename this table
     */
    @Override
    public SessionState rename(Name name) {
        return new SessionState(name, null);
    }

    /**
     * Rename this table
     */
    @Override
    public SessionState rename(Table<?> name) {
        return new SessionState(name.getQualifiedName(), null);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public SessionState where(Condition condition) {
        return new SessionState(getQualifiedName(), aliased() ? this : null, null, condition);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public SessionState where(Collection<? extends Condition> conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public SessionState where(Condition... conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public SessionState where(Field<Boolean> condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public SessionState where(SQL condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public SessionState where(@Stringly.SQL String condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public SessionState where(@Stringly.SQL String condition, Object... binds) {
        return where(DSL.condition(condition, binds));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public SessionState where(@Stringly.SQL String condition, QueryPart... parts) {
        return where(DSL.condition(condition, parts));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public SessionState whereExists(Select<?> select) {
        return where(DSL.exists(select));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public SessionState whereNotExists(Select<?> select) {
        return where(DSL.notExists(select));
    }
}