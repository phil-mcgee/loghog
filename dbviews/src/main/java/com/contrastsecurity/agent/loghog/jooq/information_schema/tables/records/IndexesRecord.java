/*
 * This file is generated by jOOQ.
 */
package com.contrtastsecurity.agent.loghog.jooq.information_schema.tables.records;


import com.contrtastsecurity.agent.loghog.jooq.information_schema.tables.Indexes;

import org.jooq.impl.TableRecordImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class IndexesRecord extends TableRecordImpl<IndexesRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * Setter for <code>INFORMATION_SCHEMA.INDEXES.INDEX_CATALOG</code>.
     */
    public void setIndexCatalog(String value) {
        set(0, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.INDEXES.INDEX_CATALOG</code>.
     */
    public String getIndexCatalog() {
        return (String) get(0);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.INDEXES.INDEX_SCHEMA</code>.
     */
    public void setIndexSchema(String value) {
        set(1, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.INDEXES.INDEX_SCHEMA</code>.
     */
    public String getIndexSchema() {
        return (String) get(1);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.INDEXES.INDEX_NAME</code>.
     */
    public void setIndexName(String value) {
        set(2, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.INDEXES.INDEX_NAME</code>.
     */
    public String getIndexName() {
        return (String) get(2);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.INDEXES.TABLE_CATALOG</code>.
     */
    public void setTableCatalog(String value) {
        set(3, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.INDEXES.TABLE_CATALOG</code>.
     */
    public String getTableCatalog() {
        return (String) get(3);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.INDEXES.TABLE_SCHEMA</code>.
     */
    public void setTableSchema(String value) {
        set(4, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.INDEXES.TABLE_SCHEMA</code>.
     */
    public String getTableSchema() {
        return (String) get(4);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.INDEXES.TABLE_NAME</code>.
     */
    public void setTableName(String value) {
        set(5, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.INDEXES.TABLE_NAME</code>.
     */
    public String getTableName() {
        return (String) get(5);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.INDEXES.INDEX_TYPE_NAME</code>.
     */
    public void setIndexTypeName(String value) {
        set(6, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.INDEXES.INDEX_TYPE_NAME</code>.
     */
    public String getIndexTypeName() {
        return (String) get(6);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.INDEXES.NULLS_DISTINCT</code>.
     */
    public void setNullsDistinct(String value) {
        set(7, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.INDEXES.NULLS_DISTINCT</code>.
     */
    public String getNullsDistinct() {
        return (String) get(7);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.INDEXES.IS_GENERATED</code>.
     */
    public void setIsGenerated(Boolean value) {
        set(8, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.INDEXES.IS_GENERATED</code>.
     */
    public Boolean getIsGenerated() {
        return (Boolean) get(8);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.INDEXES.REMARKS</code>.
     */
    public void setRemarks(String value) {
        set(9, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.INDEXES.REMARKS</code>.
     */
    public String getRemarks() {
        return (String) get(9);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.INDEXES.INDEX_CLASS</code>.
     */
    public void setIndexClass(String value) {
        set(10, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.INDEXES.INDEX_CLASS</code>.
     */
    public String getIndexClass() {
        return (String) get(10);
    }

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Create a detached IndexesRecord
     */
    public IndexesRecord() {
        super(Indexes.INDEXES);
    }

    /**
     * Create a detached, initialised IndexesRecord
     */
    public IndexesRecord(String indexCatalog, String indexSchema, String indexName, String tableCatalog, String tableSchema, String tableName, String indexTypeName, String nullsDistinct, Boolean isGenerated, String remarks, String indexClass) {
        super(Indexes.INDEXES);

        setIndexCatalog(indexCatalog);
        setIndexSchema(indexSchema);
        setIndexName(indexName);
        setTableCatalog(tableCatalog);
        setTableSchema(tableSchema);
        setTableName(tableName);
        setIndexTypeName(indexTypeName);
        setNullsDistinct(nullsDistinct);
        setIsGenerated(isGenerated);
        setRemarks(remarks);
        setIndexClass(indexClass);
        resetChangedOnNotNull();
    }
}
