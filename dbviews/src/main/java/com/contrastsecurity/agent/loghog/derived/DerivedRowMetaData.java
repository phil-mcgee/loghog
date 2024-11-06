package com.contrastsecurity.agent.loghog.derived;

import org.jooq.DataType;

public record DerivedRowMetaData(
    String columnName, DataType<?> jooqDataType, Class javaType, String extractName) {}
