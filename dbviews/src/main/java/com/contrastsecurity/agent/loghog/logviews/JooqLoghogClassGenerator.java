package com.contrastsecurity.agent.loghog.logviews;

import com.contrastsecurity.agent.loghog.JooqGenerator;

public class JooqLoghogClassGenerator {
    public static void main(String[] args) {
        JooqGenerator.jooqLoghogSources( "com.contrtastsecurity.agent.loghog.jooq",
                "dbviews/build/generated/sources/jooq/main/java");
    }
}
