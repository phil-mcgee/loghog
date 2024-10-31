package com.contrastsecurity.agent.loghog.shred;

import java.util.List;
import java.util.regex.Pattern;

public record PatternMetadata(String patternId, List<String> signatures, Pattern pattern) {}
