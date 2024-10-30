package com.contrastsecurity.agent.loghog.shred;

public interface RowClassifier {
    String MISFIT_PATTERN = "misfit";
    String ANY_PATTERN = "any";

    default String identifyPattern(Object[] sourceRow) {
        return ANY_PATTERN;
    };
}
