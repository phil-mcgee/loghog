package com.contrastsecurity.agent.loghog;

import com.contrastsecurity.agent.loghog.db.EmbeddedDatabaseFactory;
import com.contrastsecurity.agent.loghog.db.LogTable;
import com.contrastsecurity.agent.loghog.logshreds.CrumbShred;
import com.contrastsecurity.agent.loghog.logshreds.CtxShred;
import com.contrastsecurity.agent.loghog.logshreds.MesgShred;
import com.contrastsecurity.agent.loghog.logshreds.TrakShred;
import org.jooq.codegen.GenerationTool;
import org.jooq.meta.jaxb.Configuration;
import org.jooq.meta.jaxb.Database;
import org.jooq.meta.jaxb.Generator;
import org.jooq.meta.jaxb.Jdbc;
import org.jooq.meta.jaxb.Target;

import java.sql.Connection;

public class JooqGenerator {

    public static void jooqLoghogSources(final String destPackage, String destDir) {
        final String h2DbUrlRoot = "jdbc:h2:";
        final String h2DbUrlSubpath = "mem:gen;DB_CLOSE_DELAY=-1";
        try (final Connection connection = EmbeddedDatabaseFactory.create(h2DbUrlSubpath)) {
            LogTable.createLogTable(connection);
            new MesgShred().createTables(connection);
            new CrumbShred().createTables(connection);
            new TrakShred().createTables(connection);
            new CtxShred().createTables(connection);
            //            new WipAmqpShred().createTables(connection);
            //            new WipLmclShred().createTables(connection);
            //            new WipAcelShred().createTables(connection);

            Configuration configuration = new Configuration()
                    .withJdbc(new Jdbc()
                            .withDriver("org.h2.Driver")
                            .withUrl(h2DbUrlRoot + h2DbUrlSubpath))
                    .withGenerator(new Generator()
                            .withDatabase(new Database()
                                    .withName("org.jooq.meta.h2.H2Database")
                                    .withIncludes(".*")
                                    .withExcludes("")
                                    .withInputSchema(""))
                            .withTarget(new Target()
                                    .withPackageName(destPackage)
                                    .withDirectory(destDir)));

            GenerationTool.generate(configuration);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
