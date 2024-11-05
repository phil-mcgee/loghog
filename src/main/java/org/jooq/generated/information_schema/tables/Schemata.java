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
import org.jooq.generated.information_schema.tables.records.SchemataRecord;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;
import org.jooq.impl.TableImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class Schemata extends TableImpl<SchemataRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * The reference instance of <code>INFORMATION_SCHEMA.SCHEMATA</code>
     */
    public static final Schemata SCHEMATA = new Schemata();

    /**
     * The class holding records for this type
     */
    @Override
    public Class<SchemataRecord> getRecordType() {
        return SchemataRecord.class;
    }

    /**
     * The column <code>INFORMATION_SCHEMA.SCHEMATA.CATALOG_NAME</code>.
     */
    public final TableField<SchemataRecord, String> CATALOG_NAME = createField(DSL.name("CATALOG_NAME"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.SCHEMATA.SCHEMA_NAME</code>.
     */
    public final TableField<SchemataRecord, String> SCHEMA_NAME = createField(DSL.name("SCHEMA_NAME"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.SCHEMATA.SCHEMA_OWNER</code>.
     */
    public final TableField<SchemataRecord, String> SCHEMA_OWNER = createField(DSL.name("SCHEMA_OWNER"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.SCHEMATA.DEFAULT_CHARACTER_SET_CATALOG</code>.
     */
    public final TableField<SchemataRecord, String> DEFAULT_CHARACTER_SET_CATALOG = createField(DSL.name("DEFAULT_CHARACTER_SET_CATALOG"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.SCHEMATA.DEFAULT_CHARACTER_SET_SCHEMA</code>.
     */
    public final TableField<SchemataRecord, String> DEFAULT_CHARACTER_SET_SCHEMA = createField(DSL.name("DEFAULT_CHARACTER_SET_SCHEMA"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.SCHEMATA.DEFAULT_CHARACTER_SET_NAME</code>.
     */
    public final TableField<SchemataRecord, String> DEFAULT_CHARACTER_SET_NAME = createField(DSL.name("DEFAULT_CHARACTER_SET_NAME"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.SCHEMATA.SQL_PATH</code>.
     */
    public final TableField<SchemataRecord, String> SQL_PATH = createField(DSL.name("SQL_PATH"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column
     * <code>INFORMATION_SCHEMA.SCHEMATA.DEFAULT_COLLATION_NAME</code>.
     */
    public final TableField<SchemataRecord, String> DEFAULT_COLLATION_NAME = createField(DSL.name("DEFAULT_COLLATION_NAME"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.SCHEMATA.REMARKS</code>.
     */
    public final TableField<SchemataRecord, String> REMARKS = createField(DSL.name("REMARKS"), SQLDataType.VARCHAR(1000000000), this, "");

    private Schemata(Name alias, Table<SchemataRecord> aliased) {
        this(alias, aliased, (Field<?>[]) null, null);
    }

    private Schemata(Name alias, Table<SchemataRecord> aliased, Field<?>[] parameters, Condition where) {
        super(alias, null, aliased, parameters, DSL.comment(""), TableOptions.view(), where);
    }

    /**
     * Create an aliased <code>INFORMATION_SCHEMA.SCHEMATA</code> table
     * reference
     */
    public Schemata(String alias) {
        this(DSL.name(alias), SCHEMATA);
    }

    /**
     * Create an aliased <code>INFORMATION_SCHEMA.SCHEMATA</code> table
     * reference
     */
    public Schemata(Name alias) {
        this(alias, SCHEMATA);
    }

    /**
     * Create a <code>INFORMATION_SCHEMA.SCHEMATA</code> table reference
     */
    public Schemata() {
        this(DSL.name("SCHEMATA"), null);
    }

    @Override
    public Schema getSchema() {
        return aliased() ? null : InformationSchema.INFORMATION_SCHEMA;
    }

    @Override
    public Schemata as(String alias) {
        return new Schemata(DSL.name(alias), this);
    }

    @Override
    public Schemata as(Name alias) {
        return new Schemata(alias, this);
    }

    @Override
    public Schemata as(Table<?> alias) {
        return new Schemata(alias.getQualifiedName(), this);
    }

    /**
     * Rename this table
     */
    @Override
    public Schemata rename(String name) {
        return new Schemata(DSL.name(name), null);
    }

    /**
     * Rename this table
     */
    @Override
    public Schemata rename(Name name) {
        return new Schemata(name, null);
    }

    /**
     * Rename this table
     */
    @Override
    public Schemata rename(Table<?> name) {
        return new Schemata(name.getQualifiedName(), null);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Schemata where(Condition condition) {
        return new Schemata(getQualifiedName(), aliased() ? this : null, null, condition);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Schemata where(Collection<? extends Condition> conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Schemata where(Condition... conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Schemata where(Field<Boolean> condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Schemata where(SQL condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Schemata where(@Stringly.SQL String condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Schemata where(@Stringly.SQL String condition, Object... binds) {
        return where(DSL.condition(condition, binds));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Schemata where(@Stringly.SQL String condition, QueryPart... parts) {
        return where(DSL.condition(condition, parts));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Schemata whereExists(Select<?> select) {
        return where(DSL.exists(select));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Schemata whereNotExists(Select<?> select) {
        return where(DSL.notExists(select));
    }
}
