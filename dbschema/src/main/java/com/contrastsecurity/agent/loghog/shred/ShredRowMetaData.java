package com.contrastsecurity.agent.loghog.shred;

import org.jooq.DataType;

public record ShredRowMetaData(
    String columnName, DataType<?> jooqDataType, Class javaType, String extractName) {
    public ShredRowMetaData copy() {
        return new ShredRowMetaData(columnName, jooqDataType, javaType, extractName);
    }
}
