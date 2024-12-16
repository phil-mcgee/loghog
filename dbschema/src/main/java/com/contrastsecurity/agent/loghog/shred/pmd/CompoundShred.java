package com.contrastsecurity.agent.loghog.shred.pmd;

import com.contrastsecurity.agent.loghog.logshreds.ShredColumns;
import com.contrastsecurity.agent.loghog.shred.PatternMetadata;
import com.contrastsecurity.agent.loghog.shred.ShredRowMetaData;
import com.contrastsecurity.agent.loghog.shred.impl.ShredSqlTable;
import com.contrastsecurity.agent.loghog.sql.CreatableSqlTable;
import org.jooq.impl.DSL;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.contrastsecurity.agent.loghog.db.EmbeddedDatabaseFactory.jooq;
import static com.contrastsecurity.agent.loghog.db.LogTable.LOG_TABLE_NAME;

public class CompoundShred {

    public static PmdShred buildCompoundShred(
            final String tableName,
            final List<? extends PmdShred> componentShreds) {

        final List<ShredRowMetaData> compoundShredMetadata = compoundShredMetadata(componentShreds);
        return new PmdShred(
                compoundShredMetadata,
                compoundShredTable(tableName, ShredColumns.LINE, compoundShredMetadata, componentShreds),
                null,
                null,
                compoundEntrySignatures(componentShreds),
                compoundPatternMetadata(componentShreds),
                false);
    }

    private static CreatableSqlTable compoundShredTable(
            final String tableName,
            final String keyColumn,
            final List<ShredRowMetaData> compoundShredMetadata,
            final List<? extends PmdShred> componentShreds) {
       return new ShredSqlTable(tableName, compoundShredMetadata,keyColumn,
            List.of(
                    jooq()
                            .alterTable(tableName)
                            .add(
                                    DSL.constraint(tableName + "_FK_" + keyColumn)
                                            .foreignKey(keyColumn)
                                            .references(LOG_TABLE_NAME, "LINE"))
                            .getSQL()),
            compoundCreateIndicesSql(componentShreds));
    }

    private static List<ShredRowMetaData> compoundShredMetadata(List<? extends PmdShred> componentShreds) {
        final List<ShredRowMetaData> compoundShredMetadata = new ArrayList<>();
        final Set<String> extracted = new HashSet<>();
        for (final PmdShred component : componentShreds) {
            for (ShredRowMetaData smd : component.shredMetadata()) {
                if (!extracted.contains(smd.extractName())) {
                    compoundShredMetadata.add(smd.copy());
                    extracted.add(smd.extractName());
                }
            }
        }

        return compoundShredMetadata;
    }

    private static List<PatternMetadata>  compoundPatternMetadata(List<? extends PmdShred> componentShreds) {
//        return componentShreds.stream()
//                .map(shred -> (PmdShredSource)shred.shredSource())
//                .map(shredSource -> shredSource.patternMetaData)
//                .flatMap(pmdList -> pmdList.stream())
//                .toList()
//
        final List<PatternMetadata> compoundPatternMetadata = new ArrayList<>();
        final Set<String> patternIds = new HashSet<>();
        for (final PmdShred component : componentShreds) {
            final PmdShredSource shredSource = (PmdShredSource)component.shredSource();
            for (final PatternMetadata pmd : shredSource.patternMetaData) {
                if (!patternIds.contains(pmd.patternId())) {
                    patternIds.add(pmd.patternId());
                    compoundPatternMetadata.add(pmd);
                }
            }
        }

        return compoundPatternMetadata;
    }

    private static Set<String> compoundEntrySignatures(
            final List<? extends PmdShred> componentShreds) {
        return componentShreds.stream()
                .map(shred -> (PmdShredSource)shred.shredSource())
                .map(pmdShredSource -> pmdShredSource.entrySignatures())
                .flatMap(sigSet -> sigSet.stream())
                .collect(Collectors.toSet());
    }

    private static List<String> compoundCreateIndicesSql(List<? extends PmdShred> componentShreds) {
        // TODO
        return List.of();
    }

}
