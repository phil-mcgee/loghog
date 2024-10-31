package com.contrastsecurity.agent.loghog.shred;

import java.util.List;

public record PatternSignatures(String patternId, List<String> signatures) {}
