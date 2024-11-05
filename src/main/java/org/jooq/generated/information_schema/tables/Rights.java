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
import org.jooq.generated.information_schema.tables.records.RightsRecord;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;
import org.jooq.impl.TableImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class Rights extends TableImpl<RightsRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * The reference instance of <code>INFORMATION_SCHEMA.RIGHTS</code>
     */
    public static final Rights RIGHTS = new Rights();

    /**
     * The class holding records for this type
     */
    @Override
    public Class<RightsRecord> getRecordType() {
        return RightsRecord.class;
    }

    /**
     * The column <code>INFORMATION_SCHEMA.RIGHTS.GRANTEE</code>.
     */
    public final TableField<RightsRecord, String> GRANTEE = createField(DSL.name("GRANTEE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.RIGHTS.GRANTEETYPE</code>.
     */
    public final TableField<RightsRecord, String> GRANTEETYPE = createField(DSL.name("GRANTEETYPE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.RIGHTS.GRANTEDROLE</code>.
     */
    public final TableField<RightsRecord, String> GRANTEDROLE = createField(DSL.name("GRANTEDROLE"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.RIGHTS.RIGHTS</code>.
     */
    public final TableField<RightsRecord, String> RIGHTS_ = createField(DSL.name("RIGHTS"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.RIGHTS.TABLE_SCHEMA</code>.
     */
    public final TableField<RightsRecord, String> TABLE_SCHEMA = createField(DSL.name("TABLE_SCHEMA"), SQLDataType.VARCHAR(1000000000), this, "");

    /**
     * The column <code>INFORMATION_SCHEMA.RIGHTS.TABLE_NAME</code>.
     */
    public final TableField<RightsRecord, String> TABLE_NAME = createField(DSL.name("TABLE_NAME"), SQLDataType.VARCHAR(1000000000), this, "");

    private Rights(Name alias, Table<RightsRecord> aliased) {
        this(alias, aliased, (Field<?>[]) null, null);
    }

    private Rights(Name alias, Table<RightsRecord> aliased, Field<?>[] parameters, Condition where) {
        super(alias, null, aliased, parameters, DSL.comment(""), TableOptions.table(), where);
    }

    /**
     * Create an aliased <code>INFORMATION_SCHEMA.RIGHTS</code> table reference
     */
    public Rights(String alias) {
        this(DSL.name(alias), RIGHTS);
    }

    /**
     * Create an aliased <code>INFORMATION_SCHEMA.RIGHTS</code> table reference
     */
    public Rights(Name alias) {
        this(alias, RIGHTS);
    }

    /**
     * Create a <code>INFORMATION_SCHEMA.RIGHTS</code> table reference
     */
    public Rights() {
        this(DSL.name("RIGHTS"), null);
    }

    @Override
    public Schema getSchema() {
        return aliased() ? null : InformationSchema.INFORMATION_SCHEMA;
    }

    @Override
    public Rights as(String alias) {
        return new Rights(DSL.name(alias), this);
    }

    @Override
    public Rights as(Name alias) {
        return new Rights(alias, this);
    }

    @Override
    public Rights as(Table<?> alias) {
        return new Rights(alias.getQualifiedName(), this);
    }

    /**
     * Rename this table
     */
    @Override
    public Rights rename(String name) {
        return new Rights(DSL.name(name), null);
    }

    /**
     * Rename this table
     */
    @Override
    public Rights rename(Name name) {
        return new Rights(name, null);
    }

    /**
     * Rename this table
     */
    @Override
    public Rights rename(Table<?> name) {
        return new Rights(name.getQualifiedName(), null);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Rights where(Condition condition) {
        return new Rights(getQualifiedName(), aliased() ? this : null, null, condition);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Rights where(Collection<? extends Condition> conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Rights where(Condition... conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Rights where(Field<Boolean> condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Rights where(SQL condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Rights where(@Stringly.SQL String condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Rights where(@Stringly.SQL String condition, Object... binds) {
        return where(DSL.condition(condition, binds));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public Rights where(@Stringly.SQL String condition, QueryPart... parts) {
        return where(DSL.condition(condition, parts));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Rights whereExists(Select<?> select) {
        return where(DSL.exists(select));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public Rights whereNotExists(Select<?> select) {
        return where(DSL.notExists(select));
    }
}
