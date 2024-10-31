package com.contrastsecurity.agent.loghog.shred;

import org.jooq.DataType;

public record ShredRowMetaData(
    String columnName, DataType<?> jooqDataType, Class javaType, String extractName) {}
