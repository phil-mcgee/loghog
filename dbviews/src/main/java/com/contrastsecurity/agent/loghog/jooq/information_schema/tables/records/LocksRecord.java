/*
 * This file is generated by jOOQ.
 */
package com.contrtastsecurity.agent.loghog.jooq.information_schema.tables.records;


import com.contrtastsecurity.agent.loghog.jooq.information_schema.tables.Locks;

import org.jooq.impl.TableRecordImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class LocksRecord extends TableRecordImpl<LocksRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * Setter for <code>INFORMATION_SCHEMA.LOCKS.TABLE_SCHEMA</code>.
     */
    public void setTableSchema(String value) {
        set(0, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.LOCKS.TABLE_SCHEMA</code>.
     */
    public String getTableSchema() {
        return (String) get(0);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.LOCKS.TABLE_NAME</code>.
     */
    public void setTableName(String value) {
        set(1, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.LOCKS.TABLE_NAME</code>.
     */
    public String getTableName() {
        return (String) get(1);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.LOCKS.SESSION_ID</code>.
     */
    public void setSessionId(Integer value) {
        set(2, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.LOCKS.SESSION_ID</code>.
     */
    public Integer getSessionId() {
        return (Integer) get(2);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.LOCKS.LOCK_TYPE</code>.
     */
    public void setLockType(String value) {
        set(3, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.LOCKS.LOCK_TYPE</code>.
     */
    public String getLockType() {
        return (String) get(3);
    }

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Create a detached LocksRecord
     */
    public LocksRecord() {
        super(Locks.LOCKS);
    }

    /**
     * Create a detached, initialised LocksRecord
     */
    public LocksRecord(String tableSchema, String tableName, Integer sessionId, String lockType) {
        super(Locks.LOCKS);

        setTableSchema(tableSchema);
        setTableName(tableName);
        setSessionId(sessionId);
        setLockType(lockType);
        resetChangedOnNotNull();
    }
}