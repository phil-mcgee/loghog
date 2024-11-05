/*
 * This file is generated by jOOQ.
 */
package org.jooq.generated.information_schema.tables.records;


import org.jooq.generated.information_schema.tables.EnumValues;
import org.jooq.impl.TableRecordImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class EnumValuesRecord extends TableRecordImpl<EnumValuesRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * Setter for <code>INFORMATION_SCHEMA.ENUM_VALUES.OBJECT_CATALOG</code>.
     */
    public void setObjectCatalog(String value) {
        set(0, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.ENUM_VALUES.OBJECT_CATALOG</code>.
     */
    public String getObjectCatalog() {
        return (String) get(0);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.ENUM_VALUES.OBJECT_SCHEMA</code>.
     */
    public void setObjectSchema(String value) {
        set(1, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.ENUM_VALUES.OBJECT_SCHEMA</code>.
     */
    public String getObjectSchema() {
        return (String) get(1);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.ENUM_VALUES.OBJECT_NAME</code>.
     */
    public void setObjectName(String value) {
        set(2, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.ENUM_VALUES.OBJECT_NAME</code>.
     */
    public String getObjectName() {
        return (String) get(2);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.ENUM_VALUES.OBJECT_TYPE</code>.
     */
    public void setObjectType(String value) {
        set(3, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.ENUM_VALUES.OBJECT_TYPE</code>.
     */
    public String getObjectType() {
        return (String) get(3);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.ENUM_VALUES.ENUM_IDENTIFIER</code>.
     */
    public void setEnumIdentifier(String value) {
        set(4, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.ENUM_VALUES.ENUM_IDENTIFIER</code>.
     */
    public String getEnumIdentifier() {
        return (String) get(4);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.ENUM_VALUES.VALUE_NAME</code>.
     */
    public void setValueName(String value) {
        set(5, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.ENUM_VALUES.VALUE_NAME</code>.
     */
    public String getValueName() {
        return (String) get(5);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.ENUM_VALUES.VALUE_ORDINAL</code>.
     */
    public void setValueOrdinal(String value) {
        set(6, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.ENUM_VALUES.VALUE_ORDINAL</code>.
     */
    public String getValueOrdinal() {
        return (String) get(6);
    }

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Create a detached EnumValuesRecord
     */
    public EnumValuesRecord() {
        super(EnumValues.ENUM_VALUES);
    }

    /**
     * Create a detached, initialised EnumValuesRecord
     */
    public EnumValuesRecord(String objectCatalog, String objectSchema, String objectName, String objectType, String enumIdentifier, String valueName, String valueOrdinal) {
        super(EnumValues.ENUM_VALUES);

        setObjectCatalog(objectCatalog);
        setObjectSchema(objectSchema);
        setObjectName(objectName);
        setObjectType(objectType);
        setEnumIdentifier(enumIdentifier);
        setValueName(valueName);
        setValueOrdinal(valueOrdinal);
        resetChangedOnNotNull();
    }
}