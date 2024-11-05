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
import org.jooq.generated.information_schema.tables.records.CollationsRecord;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;
import org.jooq.impl.TableImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class Collations extends TableImpl<CollationsRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * The reference instance of <code>INFORMATION_SCHEMA.COLLATIONS</code>
     */
    public static final Collations COLLATIONS = new Collations();

    /**
     * The class holding records for this type
     */
    @Override
    public Class<CollationsRecord> getRecordType() {
        return CollationsRecord.class;
    }

    /**
     * The column <code>INFORMATION_SCHEMA.COLLATIONS.COLLATION_CATALOG</code>.
     */
    public final TableField<CollationsRecord, String> COLLATION_CATALOG = createField(DSL.name("COLLATION_CATALOG"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.COLLATIONS.COLLATION_SCHEMA</code>.
     */
    public final TableField<CollationsRecord, String> COLLATION_SCHEMA = createField(DSL.name("COLLATION_SCHEMA"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.COLLATIONS.COLLATION_NAME</code>.
     */
    public final TableField<CollationsRecord, String> COLLATION_NAME = createField(DSL.name("COLLATION_NAME"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.COLLATIONS.PAD_ATTRIBUTE</code>.
     */
    public final TableField<CollationsRecord, String> PAD_ATTRIBUTE = createField(DSL.name("PAD_ATTRIBUTE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.COLLATIONS.LANGUAGE_TAG</code>.
     */
    public final TableField<CollationsRecord, String> LANGUAGE_TAG = createField(DSL.name("LANGUAGE_TAG"), SQLDataType.VARCHAR(1000000000), this, "");

    private Collations(Name alias, Table<CollationsRecord> aliased) {
        this(alias, aliased, (Field<?>[]) null, null);
    }

    private Collations(Name alias, Table<CollationsRecord> aliased, Field<?>[] parameters, Condition where) {
        super(alias, null, aliased, parameters, DSL.comment(""), TableOptions.view(), where);
    }

    /**
     * Create an aliased <code>INFORMATION_SCHEMA.COLLATIONS</code> table
     * reference
     */
    public Collations(String alias) {
        this(DSL.name(alias), COLLATIONS);
    }

    /**
     * Create an aliased <code>INFORMATION_SCHEMA.COLLATIONS</code> table
     * reference
     */
    public Collations(Name alias) {
        this(alias, COLLATIONS);
    }

    /**
     * Create a <code>INFORMATION_SCHEMA.COLLATIONS</code> table reference
     */
    public Collations() {
        this(DSL.name("COLLATIONS"), null);
    }

    @Override
    public Schema getSchema() {
        return aliased() ? null : InformationSchema.INFORMATION_SCHEMA;
    }

    @Override
    public Collations as(String alias) {
        return new Collations(DSL.name(alias), this);
    }

    @Override
    public Collations as(Name alias) {
        return new Collations(alias, this);
    }

    @Override
    public Collations as(Table<?> alias) {
        return new Collations(alias.getQualifiedName(), this);
    }

    /**
     * Rename this table
     */
    @Override
    public Collations rename(String name) {
        return new Collations(DSL.name(name), null);
    }

    /**
     * Rename this table
     */
    @Override
    public Collations rename(Name name) {
        return new Collations(name, null);
    }

    /**
     * Rename this table
     */
    @Override
    public Collations rename(Table<?> name) {
        return new Collations(name.getQualifiedName(), null);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Collations where(Condition condition) {
        return new Collations(getQualifiedName(), aliased() ? this : null, null, condition);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Collations where(Collection<? extends Condition> conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Collations where(Condition... conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Collations where(Field<Boolean> condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Collations where(SQL condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Collations where(@Stringly.SQL String condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Collations where(@Stringly.SQL String condition, Object... binds) {
        return where(DSL.condition(condition, binds));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Collations where(@Stringly.SQL String condition, QueryPart... parts) {
        return where(DSL.condition(condition, parts));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Collations whereExists(Select<?> select) {
        return where(DSL.exists(select));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Collations whereNotExists(Select<?> select) {
        return where(DSL.notExists(select));
    }
}