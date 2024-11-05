/*
 * This file is generated by jOOQ.
 */
package org.jooq.generated.public_.tables.records;


import org.jooq.Record1;
import org.jooq.generated.public_.tables.Cont;
import org.jooq.impl.UpdatableRecordImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class ContRecord extends UpdatableRecordImpl<ContRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * Setter for <code>PUBLIC.CONT.LINE</code>.
     */
    public void setLine(Integer value) {
        set(0, value);
    }

    /**
     * Getter for <code>PUBLIC.CONT.LINE</code>.
     */
    public Integer getLine() {
        return (Integer) get(0);
    }

    /**
     * Setter for <code>PUBLIC.CONT.MESG</code>.
     */
    public void setMesg(Integer value) {
        set(1, value);
    }

    /**
     * Getter for <code>PUBLIC.CONT.MESG</code>.
     */
    public Integer getMesg() {
        return (Integer) get(1);
    }

    // -------------------------------------------------------------------------
    // Primary key information
    // -------------------------------------------------------------------------

    @Override
    public Record1<Integer> key() {
        return (Record1) super.key();
    }

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Create a detached ContRecord
     */
    public ContRecord() {
        super(Cont.CONT);
    }

    /**
     * Create a detached, initialised ContRecord
     */
    public ContRecord(Integer line, Integer mesg) {
        super(Cont.CONT);

        setLine(line);
        setMesg(mesg);
        resetChangedOnNotNull();
    }
}
