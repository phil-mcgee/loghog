/*
 * This file is generated by jOOQ.
 */
package com.contrtastsecurity.agent.loghog.jooq.information_schema.tables.records;


import com.contrtastsecurity.agent.loghog.jooq.information_schema.tables.Sequences;

import org.jooq.impl.TableRecordImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class SequencesRecord extends TableRecordImpl<SequencesRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * Setter for <code>INFORMATION_SCHEMA.SEQUENCES.SEQUENCE_CATALOG</code>.
     */
    public void setSequenceCatalog(String value) {
        set(0, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SEQUENCES.SEQUENCE_CATALOG</code>.
     */
    public String getSequenceCatalog() {
        return (String) get(0);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SEQUENCES.SEQUENCE_SCHEMA</code>.
     */
    public void setSequenceSchema(String value) {
        set(1, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SEQUENCES.SEQUENCE_SCHEMA</code>.
     */
    public String getSequenceSchema() {
        return (String) get(1);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SEQUENCES.SEQUENCE_NAME</code>.
     */
    public void setSequenceName(String value) {
        set(2, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SEQUENCES.SEQUENCE_NAME</code>.
     */
    public String getSequenceName() {
        return (String) get(2);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SEQUENCES.DATA_TYPE</code>.
     */
    public void setDataType(String value) {
        set(3, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SEQUENCES.DATA_TYPE</code>.
     */
    public String getDataType() {
        return (String) get(3);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SEQUENCES.NUMERIC_PRECISION</code>.
     */
    public void setNumericPrecision(Integer value) {
        set(4, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SEQUENCES.NUMERIC_PRECISION</code>.
     */
    public Integer getNumericPrecision() {
        return (Integer) get(4);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.SEQUENCES.NUMERIC_PRECISION_RADIX</code>.
     */
    public void setNumericPrecisionRadix(Integer value) {
        set(5, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.SEQUENCES.NUMERIC_PRECISION_RADIX</code>.
     */
    public Integer getNumericPrecisionRadix() {
        return (Integer) get(5);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SEQUENCES.NUMERIC_SCALE</code>.
     */
    public void setNumericScale(Integer value) {
        set(6, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SEQUENCES.NUMERIC_SCALE</code>.
     */
    public Integer getNumericScale() {
        return (Integer) get(6);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SEQUENCES.START_VALUE</code>.
     */
    public void setStartValue(Long value) {
        set(7, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SEQUENCES.START_VALUE</code>.
     */
    public Long getStartValue() {
        return (Long) get(7);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SEQUENCES.MINIMUM_VALUE</code>.
     */
    public void setMinimumValue(Long value) {
        set(8, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SEQUENCES.MINIMUM_VALUE</code>.
     */
    public Long getMinimumValue() {
        return (Long) get(8);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SEQUENCES.MAXIMUM_VALUE</code>.
     */
    public void setMaximumValue(Long value) {
        set(9, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SEQUENCES.MAXIMUM_VALUE</code>.
     */
    public Long getMaximumValue() {
        return (Long) get(9);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SEQUENCES.INCREMENT</code>.
     */
    public void setIncrement(Long value) {
        set(10, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SEQUENCES.INCREMENT</code>.
     */
    public Long getIncrement() {
        return (Long) get(10);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SEQUENCES.CYCLE_OPTION</code>.
     */
    public void setCycleOption(String value) {
        set(11, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SEQUENCES.CYCLE_OPTION</code>.
     */
    public String getCycleOption() {
        return (String) get(11);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SEQUENCES.DECLARED_DATA_TYPE</code>.
     */
    public void setDeclaredDataType(String value) {
        set(12, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SEQUENCES.DECLARED_DATA_TYPE</code>.
     */
    public String getDeclaredDataType() {
        return (String) get(12);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.SEQUENCES.DECLARED_NUMERIC_PRECISION</code>.
     */
    public void setDeclaredNumericPrecision(Integer value) {
        set(13, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.SEQUENCES.DECLARED_NUMERIC_PRECISION</code>.
     */
    public Integer getDeclaredNumericPrecision() {
        return (Integer) get(13);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.SEQUENCES.DECLARED_NUMERIC_SCALE</code>.
     */
    public void setDeclaredNumericScale(Integer value) {
        set(14, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.SEQUENCES.DECLARED_NUMERIC_SCALE</code>.
     */
    public Integer getDeclaredNumericScale() {
        return (Integer) get(14);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SEQUENCES.BASE_VALUE</code>.
     */
    public void setBaseValue(Long value) {
        set(15, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SEQUENCES.BASE_VALUE</code>.
     */
    public Long getBaseValue() {
        return (Long) get(15);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SEQUENCES.CACHE</code>.
     */
    public void setCache(Long value) {
        set(16, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SEQUENCES.CACHE</code>.
     */
    public Long getCache() {
        return (Long) get(16);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.SEQUENCES.REMARKS</code>.
     */
    public void setRemarks(String value) {
        set(17, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.SEQUENCES.REMARKS</code>.
     */
    public String getRemarks() {
        return (String) get(17);
    }

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Create a detached SequencesRecord
     */
    public SequencesRecord() {
        super(Sequences.SEQUENCES);
    }

    /**
     * Create a detached, initialised SequencesRecord
     */
    public SequencesRecord(String sequenceCatalog, String sequenceSchema, String sequenceName, String dataType, Integer numericPrecision, Integer numericPrecisionRadix, Integer numericScale, Long startValue, Long minimumValue, Long maximumValue, Long increment, String cycleOption, String declaredDataType, Integer declaredNumericPrecision, Integer declaredNumericScale, Long baseValue, Long cache, String remarks) {
        super(Sequences.SEQUENCES);

        setSequenceCatalog(sequenceCatalog);
        setSequenceSchema(sequenceSchema);
        setSequenceName(sequenceName);
        setDataType(dataType);
        setNumericPrecision(numericPrecision);
        setNumericPrecisionRadix(numericPrecisionRadix);
        setNumericScale(numericScale);
        setStartValue(startValue);
        setMinimumValue(minimumValue);
        setMaximumValue(maximumValue);
        setIncrement(increment);
        setCycleOption(cycleOption);
        setDeclaredDataType(declaredDataType);
        setDeclaredNumericPrecision(declaredNumericPrecision);
        setDeclaredNumericScale(declaredNumericScale);
        setBaseValue(baseValue);
        setCache(cache);
        setRemarks(remarks);
        resetChangedOnNotNull();
    }
}