/*
 * This file is generated by jOOQ.
 */
package com.contrtastsecurity.agent.loghog.jooq.information_schema.tables.records;


import com.contrtastsecurity.agent.loghog.jooq.information_schema.tables.Schemata;

import org.jooq.impl.TableRecordImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class SchemataRecord extends TableRecordImpl<SchemataRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * Setter for <code>INFORMATION_SCHEMA.SCHEMATA.CATALOG_NAME</code>.
     */
    public void setCatalogName(String value) {
        set(0, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SCHEMATA.CATALOG_NAME</code>.
     */
    public String getCatalogName() {
        return (String) get(0);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SCHEMATA.SCHEMA_NAME</code>.
     */
    public void setSchemaName(String value) {
        set(1, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SCHEMATA.SCHEMA_NAME</code>.
     */
    public String getSchemaName() {
        return (String) get(1);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SCHEMATA.SCHEMA_OWNER</code>.
     */
    public void setSchemaOwner(String value) {
        set(2, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SCHEMATA.SCHEMA_OWNER</code>.
     */
    public String getSchemaOwner() {
        return (String) get(2);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.SCHEMATA.DEFAULT_CHARACTER_SET_CATALOG</code>.
     */
    public void setDefaultCharacterSetCatalog(String value) {
        set(3, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.SCHEMATA.DEFAULT_CHARACTER_SET_CATALOG</code>.
     */
    public String getDefaultCharacterSetCatalog() {
        return (String) get(3);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.SCHEMATA.DEFAULT_CHARACTER_SET_SCHEMA</code>.
     */
    public void setDefaultCharacterSetSchema(String value) {
        set(4, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.SCHEMATA.DEFAULT_CHARACTER_SET_SCHEMA</code>.
     */
    public String getDefaultCharacterSetSchema() {
        return (String) get(4);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.SCHEMATA.DEFAULT_CHARACTER_SET_NAME</code>.
     */
    public void setDefaultCharacterSetName(String value) {
        set(5, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.SCHEMATA.DEFAULT_CHARACTER_SET_NAME</code>.
     */
    public String getDefaultCharacterSetName() {
        return (String) get(5);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SCHEMATA.SQL_PATH</code>.
     */
    public void setSqlPath(String value) {
        set(6, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SCHEMATA.SQL_PATH</code>.
     */
    public String getSqlPath() {
        return (String) get(6);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.SCHEMATA.DEFAULT_COLLATION_NAME</code>.
     */
    public void setDefaultCollationName(String value) {
        set(7, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.SCHEMATA.DEFAULT_COLLATION_NAME</code>.
     */
    public String getDefaultCollationName() {
        return (String) get(7);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SCHEMATA.REMARKS</code>.
     */
    public void setRemarks(String value) {
        set(8, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SCHEMATA.REMARKS</code>.
     */
    public String getRemarks() {
        return (String) get(8);
    }

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Create a detached SchemataRecord
     */
    public SchemataRecord() {
        super(Schemata.SCHEMATA);
    }

    /**
     * Create a detached, initialised SchemataRecord
     */
    public SchemataRecord(String catalogName, String schemaName, String schemaOwner, String defaultCharacterSetCatalog, String defaultCharacterSetSchema, String defaultCharacterSetName, String sqlPath, String defaultCollationName, String remarks) {
        super(Schemata.SCHEMATA);

        setCatalogName(catalogName);
        setSchemaName(schemaName);
        setSchemaOwner(schemaOwner);
        setDefaultCharacterSetCatalog(defaultCharacterSetCatalog);
        setDefaultCharacterSetSchema(defaultCharacterSetSchema);
        setDefaultCharacterSetName(defaultCharacterSetName);
        setSqlPath(sqlPath);
        setDefaultCollationName(defaultCollationName);
        setRemarks(remarks);
        resetChangedOnNotNull();
    }
}
