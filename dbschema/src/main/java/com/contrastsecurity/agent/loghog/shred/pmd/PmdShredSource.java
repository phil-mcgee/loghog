package com.contrastsecurity.agent.loghog.shred.pmd;

import com.contrastsecurity.agent.loghog.shred.impl.BaseShredSource;
import com.contrastsecurity.agent.loghog.shred.CandidateRowSelector;
import com.contrastsecurity.agent.loghog.shred.PatternMetadata;
import com.contrastsecurity.agent.loghog.shred.impl.PatternRowValuesExtractor;
import com.contrastsecurity.agent.loghog.shred.PatternSignatures;
import com.contrastsecurity.agent.loghog.shred.RowClassifier;
import com.contrastsecurity.agent.loghog.shred.RowValuesExtractor;
import com.contrastsecurity.agent.loghog.shred.ShredRowMetaData;
import com.contrastsecurity.agent.loghog.shred.ShredSource;
import com.contrastsecurity.agent.loghog.shred.impl.TextSignatureRowClassifier;
import com.contrastsecurity.agent.loghog.shred.impl.TextSignaturesCandidateRowSelector;
import com.contrastsecurity.agent.loghog.sql.BatchedSelector;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static com.contrastsecurity.agent.loghog.shred.impl.BaseShred.LOG_TABLE_ENTRY_COL;
import static com.contrastsecurity.agent.loghog.shred.impl.BaseShred.LOG_TABLE_LINE_COL;
import static com.contrastsecurity.agent.loghog.shred.impl.BaseShred.SHRED_TABLE_PATTERN_COL;

public class PmdShredSource implements ShredSource {

    final String sourceTableName;
    final List<ShredRowMetaData> shredMetaData;
    final Set<String> entrySignatures;
    final List<PatternMetadata> patternMetaData;

    final PatternRowValuesExtractor prvExtractor;
    final BaseShredSource baseShredSource;

    public PmdShredSource(final String sourceTableName,
                          final List<ShredRowMetaData> shredMetaData,
                          final Set<String> entrySignatures,
                          final List<PatternMetadata> patternMetaData) {
        this.sourceTableName = sourceTableName;
        this.shredMetaData = shredMetaData;
        this.patternMetaData = patternMetaData;
        this.entrySignatures = entrySignatures;

        this.prvExtractor = new PatternRowValuesExtractor(
                patternMap(patternMetaData),
                extractedValueNames(shredMetaData));

        this.baseShredSource = new BaseShredSource(
                sourceTableName,
                new TextSignaturesCandidateRowSelector(sourceTableName, entrySignatures),
                new TextSignatureRowClassifier(patternsSignatures(patternMetaData)),
                prvExtractor
                );
    }

    public PmdShredSource(final PmdShredSource sourcePSS,
            final Function<Pattern,Pattern> patternGroomer) {
        this.sourceTableName = sourcePSS.sourceTableName;
        this.shredMetaData = sourcePSS.shredMetaData;
        this.patternMetaData = sourcePSS.patternMetaData;
        this.entrySignatures = sourcePSS.entrySignatures;

        this.prvExtractor = new PatternRowValuesExtractor(
                sourcePSS.prvExtractor,
                patternGroomer);

        baseShredSource = new BaseShredSource(
                sourceTableName,
                new TextSignaturesCandidateRowSelector(sourceTableName, entrySignatures),
                new TextSignatureRowClassifier(patternsSignatures(patternMetaData)),
                prvExtractor);
    }

    public static List<PatternSignatures> patternsSignatures(final List<PatternMetadata> patternMetaData) {
        return patternMetaData.stream()
                .map(pmd -> new PatternSignatures(pmd.patternId(), pmd.signatures()))
                .toList();
    }

    public static List<String> extractedValueNames(final List<ShredRowMetaData> shredMetaData) {
        return shredMetaData.stream().map(srmd ->srmd.extractName())
            .filter(extractName ->
                    extractName != LOG_TABLE_LINE_COL &&
                    extractName != LOG_TABLE_ENTRY_COL &&
                    extractName != SHRED_TABLE_PATTERN_COL)
            .toList();
    }

    public static Map<String, Pattern> patternMap(final List<PatternMetadata> patternMetaData) {
        return patternMetaData.stream().collect(
                Collectors.toMap(pmd -> pmd.patternId(), pmd -> pmd.pattern()));
    }

    @Override
    public String sourceTableName() {
        return sourceTableName;
    }

    @Override
    public RowValuesExtractor rowValuesExtractor() {
        return baseShredSource.rowValuesExtractor();
    }

    @Override
    public RowClassifier rowClassifier() {
        return baseShredSource.rowClassifier();
    }

    @Override
    public int batchSize() {
        return baseShredSource.batchSize();
    }

    @Override
    public BatchedSelector openCandidateRowSelector(Connection connection) throws SQLException {
        return baseShredSource.openCandidateRowSelector(connection);
    }

    @Override
    public CandidateRowSelector candidateRowSelector() {
        return baseShredSource.candidateRowSelector();
    }

    public List<ShredRowMetaData> shredMetaData() {
        return shredMetaData;
    }

    public Set<String> entrySignatures() {
        return entrySignatures;
    }

    public List<PatternMetadata> patternMetaData() {
        return patternMetaData;
    }
}
