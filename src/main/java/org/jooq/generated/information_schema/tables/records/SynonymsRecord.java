/*
 * This file is generated by jOOQ.
 */
package org.jooq.generated.information_schema.tables.records;


import org.jooq.generated.information_schema.tables.Synonyms;
import org.jooq.impl.TableRecordImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class SynonymsRecord extends TableRecordImpl<SynonymsRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * Setter for <code>INFORMATION_SCHEMA.SYNONYMS.SYNONYM_CATALOG</code>.
     */
    public void setSynonymCatalog(String value) {
        set(0, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SYNONYMS.SYNONYM_CATALOG</code>.
     */
    public String getSynonymCatalog() {
        return (String) get(0);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SYNONYMS.SYNONYM_SCHEMA</code>.
     */
    public void setSynonymSchema(String value) {
        set(1, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SYNONYMS.SYNONYM_SCHEMA</code>.
     */
    public String getSynonymSchema() {
        return (String) get(1);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SYNONYMS.SYNONYM_NAME</code>.
     */
    public void setSynonymName(String value) {
        set(2, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SYNONYMS.SYNONYM_NAME</code>.
     */
    public String getSynonymName() {
        return (String) get(2);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SYNONYMS.SYNONYM_FOR</code>.
     */
    public void setSynonymFor(String value) {
        set(3, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SYNONYMS.SYNONYM_FOR</code>.
     */
    public String getSynonymFor() {
        return (String) get(3);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SYNONYMS.SYNONYM_FOR_SCHEMA</code>.
     */
    public void setSynonymForSchema(String value) {
        set(4, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SYNONYMS.SYNONYM_FOR_SCHEMA</code>.
     */
    public String getSynonymForSchema() {
        return (String) get(4);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SYNONYMS.TYPE_NAME</code>.
     */
    public void setTypeName(String value) {
        set(5, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SYNONYMS.TYPE_NAME</code>.
     */
    public String getTypeName() {
        return (String) get(5);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SYNONYMS.STATUS</code>.
     */
    public void setStatus(String value) {
        set(6, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SYNONYMS.STATUS</code>.
     */
    public String getStatus() {
        return (String) get(6);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SYNONYMS.REMARKS</code>.
     */
    public void setRemarks(String value) {
        set(7, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SYNONYMS.REMARKS</code>.
     */
    public String getRemarks() {
        return (String) get(7);
    }

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Create a detached SynonymsRecord
     */
    public SynonymsRecord() {
        super(Synonyms.SYNONYMS);
    }

    /**
     * Create a detached, initialised SynonymsRecord
     */
    public SynonymsRecord(String synonymCatalog, String synonymSchema, String synonymName, String synonymFor, String synonymForSchema, String typeName, String status, String remarks) {
        super(Synonyms.SYNONYMS);

        setSynonymCatalog(synonymCatalog);
        setSynonymSchema(synonymSchema);
        setSynonymName(synonymName);
        setSynonymFor(synonymFor);
        setSynonymForSchema(synonymForSchema);
        setTypeName(typeName);
        setStatus(status);
        setRemarks(remarks);
        resetChangedOnNotNull();
    }
}
