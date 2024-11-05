/*
 * This file is generated by jOOQ.
 */
package com.contrtastsecurity.agent.loghog.jooq.information_schema.tables.records;


import com.contrtastsecurity.agent.loghog.jooq.information_schema.tables.Columns;

import org.jooq.impl.TableRecordImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class ColumnsRecord extends TableRecordImpl<ColumnsRecord> {

    private static final long serialVersionUID = 1L;

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.TABLE_CATALOG</code>.
     */
    public void setTableCatalog(String value) {
        set(0, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.TABLE_CATALOG</code>.
     */
    public String getTableCatalog() {
        return (String) get(0);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.TABLE_SCHEMA</code>.
     */
    public void setTableSchema(String value) {
        set(1, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.TABLE_SCHEMA</code>.
     */
    public String getTableSchema() {
        return (String) get(1);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.TABLE_NAME</code>.
     */
    public void setTableName(String value) {
        set(2, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.TABLE_NAME</code>.
     */
    public String getTableName() {
        return (String) get(2);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.COLUMN_NAME</code>.
     */
    public void setColumnName(String value) {
        set(3, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.COLUMN_NAME</code>.
     */
    public String getColumnName() {
        return (String) get(3);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.ORDINAL_POSITION</code>.
     */
    public void setOrdinalPosition(Integer value) {
        set(4, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.ORDINAL_POSITION</code>.
     */
    public Integer getOrdinalPosition() {
        return (Integer) get(4);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.COLUMN_DEFAULT</code>.
     */
    public void setColumnDefault(String value) {
        set(5, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.COLUMN_DEFAULT</code>.
     */
    public String getColumnDefault() {
        return (String) get(5);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.IS_NULLABLE</code>.
     */
    public void setIsNullable(String value) {
        set(6, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.IS_NULLABLE</code>.
     */
    public String getIsNullable() {
        return (String) get(6);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.DATA_TYPE</code>.
     */
    public void setDataType(String value) {
        set(7, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.DATA_TYPE</code>.
     */
    public String getDataType() {
        return (String) get(7);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.COLUMNS.CHARACTER_MAXIMUM_LENGTH</code>.
     */
    public void setCharacterMaximumLength(Long value) {
        set(8, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.COLUMNS.CHARACTER_MAXIMUM_LENGTH</code>.
     */
    public Long getCharacterMaximumLength() {
        return (Long) get(8);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.COLUMNS.CHARACTER_OCTET_LENGTH</code>.
     */
    public void setCharacterOctetLength(Long value) {
        set(9, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.COLUMNS.CHARACTER_OCTET_LENGTH</code>.
     */
    public Long getCharacterOctetLength() {
        return (Long) get(9);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.NUMERIC_PRECISION</code>.
     */
    public void setNumericPrecision(Integer value) {
        set(10, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.NUMERIC_PRECISION</code>.
     */
    public Integer getNumericPrecision() {
        return (Integer) get(10);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.COLUMNS.NUMERIC_PRECISION_RADIX</code>.
     */
    public void setNumericPrecisionRadix(Integer value) {
        set(11, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.COLUMNS.NUMERIC_PRECISION_RADIX</code>.
     */
    public Integer getNumericPrecisionRadix() {
        return (Integer) get(11);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.NUMERIC_SCALE</code>.
     */
    public void setNumericScale(Integer value) {
        set(12, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.NUMERIC_SCALE</code>.
     */
    public Integer getNumericScale() {
        return (Integer) get(12);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.DATETIME_PRECISION</code>.
     */
    public void setDatetimePrecision(Integer value) {
        set(13, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.DATETIME_PRECISION</code>.
     */
    public Integer getDatetimePrecision() {
        return (Integer) get(13);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.INTERVAL_TYPE</code>.
     */
    public void setIntervalType(String value) {
        set(14, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.INTERVAL_TYPE</code>.
     */
    public String getIntervalType() {
        return (String) get(14);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.INTERVAL_PRECISION</code>.
     */
    public void setIntervalPrecision(Integer value) {
        set(15, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.INTERVAL_PRECISION</code>.
     */
    public Integer getIntervalPrecision() {
        return (Integer) get(15);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.CHARACTER_SET_CATALOG</code>.
     */
    public void setCharacterSetCatalog(String value) {
        set(16, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.CHARACTER_SET_CATALOG</code>.
     */
    public String getCharacterSetCatalog() {
        return (String) get(16);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.CHARACTER_SET_SCHEMA</code>.
     */
    public void setCharacterSetSchema(String value) {
        set(17, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.CHARACTER_SET_SCHEMA</code>.
     */
    public String getCharacterSetSchema() {
        return (String) get(17);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.CHARACTER_SET_NAME</code>.
     */
    public void setCharacterSetName(String value) {
        set(18, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.CHARACTER_SET_NAME</code>.
     */
    public String getCharacterSetName() {
        return (String) get(18);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.COLLATION_CATALOG</code>.
     */
    public void setCollationCatalog(String value) {
        set(19, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.COLLATION_CATALOG</code>.
     */
    public String getCollationCatalog() {
        return (String) get(19);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.COLLATION_SCHEMA</code>.
     */
    public void setCollationSchema(String value) {
        set(20, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.COLLATION_SCHEMA</code>.
     */
    public String getCollationSchema() {
        return (String) get(20);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.COLLATION_NAME</code>.
     */
    public void setCollationName(String value) {
        set(21, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.COLLATION_NAME</code>.
     */
    public String getCollationName() {
        return (String) get(21);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.DOMAIN_CATALOG</code>.
     */
    public void setDomainCatalog(String value) {
        set(22, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.DOMAIN_CATALOG</code>.
     */
    public String getDomainCatalog() {
        return (String) get(22);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.DOMAIN_SCHEMA</code>.
     */
    public void setDomainSchema(String value) {
        set(23, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.DOMAIN_SCHEMA</code>.
     */
    public String getDomainSchema() {
        return (String) get(23);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.DOMAIN_NAME</code>.
     */
    public void setDomainName(String value) {
        set(24, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.DOMAIN_NAME</code>.
     */
    public String getDomainName() {
        return (String) get(24);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.MAXIMUM_CARDINALITY</code>.
     */
    public void setMaximumCardinality(Integer value) {
        set(25, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.MAXIMUM_CARDINALITY</code>.
     */
    public Integer getMaximumCardinality() {
        return (Integer) get(25);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.DTD_IDENTIFIER</code>.
     */
    public void setDtdIdentifier(String value) {
        set(26, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.DTD_IDENTIFIER</code>.
     */
    public String getDtdIdentifier() {
        return (String) get(26);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.IS_IDENTITY</code>.
     */
    public void setIsIdentity(String value) {
        set(27, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.IS_IDENTITY</code>.
     */
    public String getIsIdentity() {
        return (String) get(27);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.IDENTITY_GENERATION</code>.
     */
    public void setIdentityGeneration(String value) {
        set(28, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.IDENTITY_GENERATION</code>.
     */
    public String getIdentityGeneration() {
        return (String) get(28);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.IDENTITY_START</code>.
     */
    public void setIdentityStart(Long value) {
        set(29, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.IDENTITY_START</code>.
     */
    public Long getIdentityStart() {
        return (Long) get(29);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.IDENTITY_INCREMENT</code>.
     */
    public void setIdentityIncrement(Long value) {
        set(30, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.IDENTITY_INCREMENT</code>.
     */
    public Long getIdentityIncrement() {
        return (Long) get(30);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.IDENTITY_MAXIMUM</code>.
     */
    public void setIdentityMaximum(Long value) {
        set(31, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.IDENTITY_MAXIMUM</code>.
     */
    public Long getIdentityMaximum() {
        return (Long) get(31);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.IDENTITY_MINIMUM</code>.
     */
    public void setIdentityMinimum(Long value) {
        set(32, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.IDENTITY_MINIMUM</code>.
     */
    public Long getIdentityMinimum() {
        return (Long) get(32);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.IDENTITY_CYCLE</code>.
     */
    public void setIdentityCycle(String value) {
        set(33, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.IDENTITY_CYCLE</code>.
     */
    public String getIdentityCycle() {
        return (String) get(33);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.IS_GENERATED</code>.
     */
    public void setIsGenerated(String value) {
        set(34, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.IS_GENERATED</code>.
     */
    public String getIsGenerated() {
        return (String) get(34);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.GENERATION_EXPRESSION</code>.
     */
    public void setGenerationExpression(String value) {
        set(35, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.GENERATION_EXPRESSION</code>.
     */
    public String getGenerationExpression() {
        return (String) get(35);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.DECLARED_DATA_TYPE</code>.
     */
    public void setDeclaredDataType(String value) {
        set(36, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.DECLARED_DATA_TYPE</code>.
     */
    public String getDeclaredDataType() {
        return (String) get(36);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.COLUMNS.DECLARED_NUMERIC_PRECISION</code>.
     */
    public void setDeclaredNumericPrecision(Integer value) {
        set(37, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.COLUMNS.DECLARED_NUMERIC_PRECISION</code>.
     */
    public Integer getDeclaredNumericPrecision() {
        return (Integer) get(37);
    }

    /**
     * Setter for
     * <code>INFORMATION_SCHEMA.COLUMNS.DECLARED_NUMERIC_SCALE</code>.
     */
    public void setDeclaredNumericScale(Integer value) {
        set(38, value);
    }

    /**
     * Getter for
     * <code>INFORMATION_SCHEMA.COLUMNS.DECLARED_NUMERIC_SCALE</code>.
     */
    public Integer getDeclaredNumericScale() {
        return (Integer) get(38);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.GEOMETRY_TYPE</code>.
     */
    public void setGeometryType(String value) {
        set(39, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.GEOMETRY_TYPE</code>.
     */
    public String getGeometryType() {
        return (String) get(39);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.GEOMETRY_SRID</code>.
     */
    public void setGeometrySrid(Integer value) {
        set(40, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.GEOMETRY_SRID</code>.
     */
    public Integer getGeometrySrid() {
        return (Integer) get(40);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.IDENTITY_BASE</code>.
     */
    public void setIdentityBase(Long value) {
        set(41, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.IDENTITY_BASE</code>.
     */
    public Long getIdentityBase() {
        return (Long) get(41);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.IDENTITY_CACHE</code>.
     */
    public void setIdentityCache(Long value) {
        set(42, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.IDENTITY_CACHE</code>.
     */
    public Long getIdentityCache() {
        return (Long) get(42);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.COLUMN_ON_UPDATE</code>.
     */
    public void setColumnOnUpdate(String value) {
        set(43, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.COLUMN_ON_UPDATE</code>.
     */
    public String getColumnOnUpdate() {
        return (String) get(43);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.IS_VISIBLE</code>.
     */
    public void setIsVisible(Boolean value) {
        set(44, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.IS_VISIBLE</code>.
     */
    public Boolean getIsVisible() {
        return (Boolean) get(44);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.DEFAULT_ON_NULL</code>.
     */
    public void setDefaultOnNull(Boolean value) {
        set(45, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.DEFAULT_ON_NULL</code>.
     */
    public Boolean getDefaultOnNull() {
        return (Boolean) get(45);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.SELECTIVITY</code>.
     */
    public void setSelectivity(Integer value) {
        set(46, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.SELECTIVITY</code>.
     */
    public Integer getSelectivity() {
        return (Integer) get(46);
    }

    /**
     * Setter for <code>INFORMATION_SCHEMA.COLUMNS.REMARKS</code>.
     */
    public void setRemarks(String value) {
        set(47, value);
    }

    /**
     * Getter for <code>INFORMATION_SCHEMA.COLUMNS.REMARKS</code>.
     */
    public String getRemarks() {
        return (String) get(47);
    }

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Create a detached ColumnsRecord
     */
    public ColumnsRecord() {
        super(Columns.COLUMNS);
    }

    /**
     * Create a detached, initialised ColumnsRecord
     */
    public ColumnsRecord(String tableCatalog, String tableSchema, String tableName, String columnName, Integer ordinalPosition, String columnDefault, String isNullable, String dataType, Long characterMaximumLength, Long characterOctetLength, Integer numericPrecision, Integer numericPrecisionRadix, Integer numericScale, Integer datetimePrecision, String intervalType, Integer intervalPrecision, String characterSetCatalog, String characterSetSchema, String characterSetName, String collationCatalog, String collationSchema, String collationName, String domainCatalog, String domainSchema, String domainName, Integer maximumCardinality, String dtdIdentifier, String isIdentity, String identityGeneration, Long identityStart, Long identityIncrement, Long identityMaximum, Long identityMinimum, String identityCycle, String isGenerated, String generationExpression, String declaredDataType, Integer declaredNumericPrecision, Integer declaredNumericScale, String geometryType, Integer geometrySrid, Long identityBase, Long identityCache, String columnOnUpdate, Boolean isVisible, Boolean defaultOnNull, Integer selectivity, String remarks) {
        super(Columns.COLUMNS);

        setTableCatalog(tableCatalog);
        setTableSchema(tableSchema);
        setTableName(tableName);
        setColumnName(columnName);
        setOrdinalPosition(ordinalPosition);
        setColumnDefault(columnDefault);
        setIsNullable(isNullable);
        setDataType(dataType);
        setCharacterMaximumLength(characterMaximumLength);
        setCharacterOctetLength(characterOctetLength);
        setNumericPrecision(numericPrecision);
        setNumericPrecisionRadix(numericPrecisionRadix);
        setNumericScale(numericScale);
        setDatetimePrecision(datetimePrecision);
        setIntervalType(intervalType);
        setIntervalPrecision(intervalPrecision);
        setCharacterSetCatalog(characterSetCatalog);
        setCharacterSetSchema(characterSetSchema);
        setCharacterSetName(characterSetName);
        setCollationCatalog(collationCatalog);
        setCollationSchema(collationSchema);
        setCollationName(collationName);
        setDomainCatalog(domainCatalog);
        setDomainSchema(domainSchema);
        setDomainName(domainName);
        setMaximumCardinality(maximumCardinality);
        setDtdIdentifier(dtdIdentifier);
        setIsIdentity(isIdentity);
        setIdentityGeneration(identityGeneration);
        setIdentityStart(identityStart);
        setIdentityIncrement(identityIncrement);
        setIdentityMaximum(identityMaximum);
        setIdentityMinimum(identityMinimum);
        setIdentityCycle(identityCycle);
        setIsGenerated(isGenerated);
        setGenerationExpression(generationExpression);
        setDeclaredDataType(declaredDataType);
        setDeclaredNumericPrecision(declaredNumericPrecision);
        setDeclaredNumericScale(declaredNumericScale);
        setGeometryType(geometryType);
        setGeometrySrid(geometrySrid);
        setIdentityBase(identityBase);
        setIdentityCache(identityCache);
        setColumnOnUpdate(columnOnUpdate);
        setIsVisible(isVisible);
        setDefaultOnNull(defaultOnNull);
        setSelectivity(selectivity);
        setRemarks(remarks);
        resetChangedOnNotNull();
    }
}