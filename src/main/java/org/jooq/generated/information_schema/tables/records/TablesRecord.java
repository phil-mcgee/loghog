/*
 * This file is generated by jOOQ.
 */
package org.jooq.generated.information_schema.tables.records;


import org.jooq.generated.information_schema.tables.Tables;
import org.jooq.impl.TableRecordImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class TablesRecord extends TableRecordImpl<TablesRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * Setter for <code>INFORMATION_SCHEMA.TABLES.TABLE_CATALOG</code>.
     */
    public void setTableCatalog(String value) {
        set(0, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.TABLES.TABLE_CATALOG</code>.
     */
    public String getTableCatalog() {
        return (String) get(0);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.TABLES.TABLE_SCHEMA</code>.
     */
    public void setTableSchema(String value) {
        set(1, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.TABLES.TABLE_SCHEMA</code>.
     */
    public String getTableSchema() {
        return (String) get(1);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.TABLES.TABLE_NAME</code>.
     */
    public void setTableName(String value) {
        set(2, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.TABLES.TABLE_NAME</code>.
     */
    public String getTableName() {
        return (String) get(2);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.TABLES.TABLE_TYPE</code>.
     */
    public void setTableType(String value) {
        set(3, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.TABLES.TABLE_TYPE</code>.
     */
    public String getTableType() {
        return (String) get(3);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.TABLES.IS_INSERTABLE_INTO</code>.
     */
    public void setIsInsertableInto(String value) {
        set(4, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.TABLES.IS_INSERTABLE_INTO</code>.
     */
    public String getIsInsertableInto() {
        return (String) get(4);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.TABLES.COMMIT_ACTION</code>.
     */
    public void setCommitAction(String value) {
        set(5, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.TABLES.COMMIT_ACTION</code>.
     */
    public String getCommitAction() {
        return (String) get(5);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.TABLES.STORAGE_TYPE</code>.
     */
    public void setStorageType(String value) {
        set(6, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.TABLES.STORAGE_TYPE</code>.
     */
    public String getStorageType() {
        return (String) get(6);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.TABLES.REMARKS</code>.
     */
    public void setRemarks(String value) {
        set(7, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.TABLES.REMARKS</code>.
     */
    public String getRemarks() {
        return (String) get(7);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.TABLES.LAST_MODIFICATION</code>.
     */
    public void setLastModification(Long value) {
        set(8, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.TABLES.LAST_MODIFICATION</code>.
     */
    public Long getLastModification() {
        return (Long) get(8);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.TABLES.TABLE_CLASS</code>.
     */
    public void setTableClass(String value) {
        set(9, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.TABLES.TABLE_CLASS</code>.
     */
    public String getTableClass() {
        return (String) get(9);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.TABLES.ROW_COUNT_ESTIMATE</code>.
     */
    public void setRowCountEstimate(Long value) {
        set(10, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.TABLES.ROW_COUNT_ESTIMATE</code>.
     */
    public Long getRowCountEstimate() {
        return (Long) get(10);
    }

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Create a detached TablesRecord
     */
    public TablesRecord() {
        super(Tables.TABLES);
    }

    /**
     * Create a detached, initialised TablesRecord
     */
    public TablesRecord(String tableCatalog, String tableSchema, String tableName, String tableType, String isInsertableInto, String commitAction, String storageType, String remarks, Long lastModification, String tableClass, Long rowCountEstimate) {
        super(Tables.TABLES);

        setTableCatalog(tableCatalog);
        setTableSchema(tableSchema);
        setTableName(tableName);
        setTableType(tableType);
        setIsInsertableInto(isInsertableInto);
        setCommitAction(commitAction);
        setStorageType(storageType);
        setRemarks(remarks);
        setLastModification(lastModification);
        setTableClass(tableClass);
        setRowCountEstimate(rowCountEstimate);
        resetChangedOnNotNull();
    }
}
