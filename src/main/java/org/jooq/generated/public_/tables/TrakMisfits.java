/*
 * This file is generated by jOOQ.
 */
package org.jooq.generated.public_.tables;


import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.jooq.Condition;
import org.jooq.Field;
import org.jooq.ForeignKey;
import org.jooq.InverseForeignKey;
import org.jooq.Name;
import org.jooq.Path;
import org.jooq.PlainSQL;
import org.jooq.QueryPart;
import org.jooq.Record;
import org.jooq.SQL;
import org.jooq.Schema;
import org.jooq.Select;
import org.jooq.Stringly;
import org.jooq.Table;
import org.jooq.TableField;
import org.jooq.TableOptions;
import org.jooq.UniqueKey;
import org.jooq.generated.public_.Keys;
import org.jooq.generated.public_.Public;
import org.jooq.generated.public_.tables.Log.LogPath;
import org.jooq.generated.public_.tables.records.TrakMisfitsRecord;
import org.jooq.impl.DSL;
import org.jooq.impl.SQLDataType;
import org.jooq.impl.TableImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class TrakMisfits extends TableImpl<TrakMisfitsRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * The reference instance of <code>PUBLIC.TRAK_MISFITS</code>
     */
    public static final TrakMisfits TRAK_MISFITS = new TrakMisfits();

    /**
     * The class holding records for this type
     */
    @Override
    public Class<TrakMisfitsRecord> getRecordType() {
        return TrakMisfitsRecord.class;
    }

    /**
     * The column <code>PUBLIC.TRAK_MISFITS.LINE</code>.
     */
    public final TableField<TrakMisfitsRecord, Integer> LINE = createField(DSL.name("LINE"), SQLDataType.INTEGER.nullable(false), this, "");

    private TrakMisfits(Name alias, Table<TrakMisfitsRecord> aliased) {
        this(alias, aliased, (Field<?>[]) null, null);
    }

    private TrakMisfits(Name alias, Table<TrakMisfitsRecord> aliased, Field<?>[] parameters, Condition where) {
        super(alias, null, aliased, parameters, DSL.comment(""), TableOptions.table(), where);
    }

    /**
     * Create an aliased <code>PUBLIC.TRAK_MISFITS</code> table reference
     */
    public TrakMisfits(String alias) {
        this(DSL.name(alias), TRAK_MISFITS);
    }

    /**
     * Create an aliased <code>PUBLIC.TRAK_MISFITS</code> table reference
     */
    public TrakMisfits(Name alias) {
        this(alias, TRAK_MISFITS);
    }

    /**
     * Create a <code>PUBLIC.TRAK_MISFITS</code> table reference
     */
    public TrakMisfits() {
        this(DSL.name("TRAK_MISFITS"), null);
    }

    public <O extends Record> TrakMisfits(Table<O> path, ForeignKey<O, TrakMisfitsRecord> childPath, InverseForeignKey<O, TrakMisfitsRecord> parentPath) {
        super(path, childPath, parentPath, TRAK_MISFITS);
    }

    /**
     * A subtype implementing {@link Path} for simplified path-based joins.
     */
    public static class TrakMisfitsPath extends TrakMisfits implements Path<TrakMisfitsRecord> {

        private static final long serialVersionUID = 1L;
        public <O extends Record> TrakMisfitsPath(Table<O> path, ForeignKey<O, TrakMisfitsRecord> childPath, InverseForeignKey<O, TrakMisfitsRecord> parentPath) {
            super(path, childPath, parentPath);
        }
        private TrakMisfitsPath(Name alias, Table<TrakMisfitsRecord> aliased) {
            super(alias, aliased);
        }

        @Override
        public TrakMisfitsPath as(String alias) {
            return new TrakMisfitsPath(DSL.name(alias), this);
        }

        @Override
        public TrakMisfitsPath as(Name alias) {
            return new TrakMisfitsPath(alias, this);
        }

        @Override
        public TrakMisfitsPath as(Table<?> alias) {
            return new TrakMisfitsPath(alias.getQualifiedName(), this);
        }
    }

    @Override
    public Schema getSchema() {
        return aliased() ? null : Public.PUBLIC;
    }

    @Override
    public UniqueKey<TrakMisfitsRecord> getPrimaryKey() {
        return Keys.CONSTRAINT_A;
    }

    @Override
    public List<ForeignKey<TrakMisfitsRecord, ?>> getReferences() {
        return Arrays.asList(Keys.TRAK_MISFITS_FK_LINE);
    }

    private transient LogPath _log;

    /**
     * Get the implicit join path to the <code>PUBLIC.LOG</code> table.
     */
    public LogPath log() {
        if (_log == null)
            _log = new LogPath(this, Keys.TRAK_MISFITS_FK_LINE, null);

        return _log;
    }

    @Override
    public TrakMisfits as(String alias) {
        return new TrakMisfits(DSL.name(alias), this);
    }

    @Override
    public TrakMisfits as(Name alias) {
        return new TrakMisfits(alias, this);
    }

    @Override
    public TrakMisfits as(Table<?> alias) {
        return new TrakMisfits(alias.getQualifiedName(), this);
    }

    /**
     * Rename this table
     */
    @Override
    public TrakMisfits rename(String name) {
        return new TrakMisfits(DSL.name(name), null);
    }

    /**
     * Rename this table
     */
    @Override
    public TrakMisfits rename(Name name) {
        return new TrakMisfits(name, null);
    }

    /**
     * Rename this table
     */
    @Override
    public TrakMisfits rename(Table<?> name) {
        return new TrakMisfits(name.getQualifiedName(), null);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public TrakMisfits where(Condition condition) {
        return new TrakMisfits(getQualifiedName(), aliased() ? this : null, null, condition);
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public TrakMisfits where(Collection<? extends Condition> conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public TrakMisfits where(Condition... conditions) {
        return where(DSL.and(conditions));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public TrakMisfits where(Field<Boolean> condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public TrakMisfits where(SQL condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public TrakMisfits where(@Stringly.SQL String condition) {
        return where(DSL.condition(condition));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public TrakMisfits where(@Stringly.SQL String condition, Object... binds) {
        return where(DSL.condition(condition, binds));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    @PlainSQL
    public TrakMisfits where(@Stringly.SQL String condition, QueryPart... parts) {
        return where(DSL.condition(condition, parts));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public TrakMisfits whereExists(Select<?> select) {
        return where(DSL.exists(select));
    }

    /**
     * Create an inline derived table from this table
     */
    @Override
    public TrakMisfits whereNotExists(Select<?> select) {
        return where(DSL.notExists(select));
    }
}
