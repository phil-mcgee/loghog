package com.contrastsecurity.agent.loghog.shred.pmd;

import com.contrastsecurity.agent.loghog.shred.impl.BaseShred;
import com.contrastsecurity.agent.loghog.shred.PatternMetadata;
import com.contrastsecurity.agent.loghog.shred.ShredRowMetaData;
import com.contrastsecurity.agent.loghog.sql.CreatableSqlTable;

import java.util.List;
import java.util.Set;

import static com.contrastsecurity.agent.loghog.db.LogTable.LOG_TABLE_NAME;

public class PmdShred extends BaseShred {

    public PmdShred(
            final List<ShredRowMetaData> shredMetadata,
            final CreatableSqlTable shredTable,
            final List<ShredRowMetaData> misfitsMetadata,
            final CreatableSqlTable misfitsTable,
            final Set<String> entrySignatures,
            final List<PatternMetadata> patternMetaData,
            final boolean showMisfits) {
        super(shredMetadata, shredTable,
                misfitsMetadata, misfitsTable,
                new PmdShredSource(LOG_TABLE_NAME,
                        shredMetadata,
                        entrySignatures,
                        patternMetaData),
                showMisfits);
    }
}
