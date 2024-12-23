/* (C)2024 */
package com.contrastsecurity.agent.loghog;

import static com.contrastsecurity.agent.loghog.shred.pmd.CompoundShred.buildCompoundShred;

import com.contrastsecurity.agent.loghog.db.EmbeddedDatabaseFactory;
import com.contrastsecurity.agent.loghog.db.LogTable;
import com.contrastsecurity.agent.loghog.logshreds.CrumbShred;
import com.contrastsecurity.agent.loghog.logshreds.CtxShred;
import com.contrastsecurity.agent.loghog.logshreds.FluxShred;
import com.contrastsecurity.agent.loghog.logshreds.HttpShred;
import com.contrastsecurity.agent.loghog.logshreds.MesgShred;
import com.contrastsecurity.agent.loghog.logshreds.TrakShred;
import com.contrastsecurity.agent.loghog.logshreds.VulnShred;
import com.contrastsecurity.agent.loghog.logviews.ViewCreator;
import com.contrastsecurity.agent.loghog.shred.pmd.PmdShred;
import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;

public class LogHog {

  final ConnectionProvider connectionProvider;

  public LogHog(final ConnectionProvider connectionProvider) {
    this.connectionProvider = connectionProvider;
  }

  abstract static class ConnectionProvider {
    public abstract Connection connect() throws SQLException;
  }

  void createAndPopulateDb(final String logFilepath) {
    try (final Connection connection = connectionProvider.connect()) {
      LogTable.initializeLogTable(connection, logFilepath);
      new MesgShred().createAndPopulateShredTables(connection);
      new CrumbShred().createAndPopulateShredTables(connection);

      final PmdShred trakShred = new TrakShred();
      trakShred.createAndPopulateShredTables(connection);

      final PmdShred ctxShred = new CtxShred();
      ctxShred.createAndPopulateShredTables(connection);

      new HttpShred().createAndPopulateShredTables(connection);

      final PmdShred fluxShred = new FluxShred();
      fluxShred.createAndPopulateShredTables(connection);

      new VulnShred().createAndPopulateShredTables(connection);

      PmdShred mfluxShred = buildCompoundShred("MFLUX", List.of(fluxShred, ctxShred, trakShred));
      mfluxShred.createAndPopulateShredTables(connection);
      //            new WipAmqpShred().createTables(connection);
      //            new WipLmclShred().createTables(connection);
      //            new WipAcelShred().createTables(connection);
    } catch (SQLException | IOException e) {
      e.printStackTrace();
    }
  }

  public void createViews() {
    try (final Connection connection = connectionProvider.connect()) {

    } catch (SQLException e) {
      e.printStackTrace();
    }
  }

  public static void main(String[] args) throws Exception {
    if (args.length < 1) {
      System.out.println(
          "loghog requires a comand line argument specifying the path to a log file to"
              + " load, e.g.: ");
      System.out.println("java -jar loghog-all.jar ~/logs/some-log.err");
      System.exit(1);
    }
    final String logFilepath = args[0];
    final File logFile = new File(logFilepath);
    if (!logFile.exists() || !logFile.isFile() || !logFile.canRead()) {
      System.out.println("Log file does not exist or is not readable: " + logFilepath);
      System.exit(2);
    }
    System.out.println("Parsing Java Agent log file: " + logFilepath);

    final String dbFilepathNoSuffix;
    final String dbFilepath;
    if (args.length < 2) {
      dbFilepathNoSuffix = logFilepath.substring(0, logFilepath.lastIndexOf('.'));
      dbFilepath = dbFilepathNoSuffix + EmbeddedDatabaseFactory.DB_FILE_EXTENSION;
      System.out.println("Using default database file: " + dbFilepath);
    } else {
      dbFilepathNoSuffix = args[1].substring(0, logFilepath.lastIndexOf('.'));
      dbFilepath = dbFilepathNoSuffix + EmbeddedDatabaseFactory.DB_FILE_EXTENSION;
      System.out.println("Using specified database file: " + dbFilepath);
    }

    final File dbFile = new File(dbFilepath);
    if (dbFile.exists()) {
      if (!dbFile.canWrite()) {
        System.out.println("Database file is not writable: " + dbFilepath);
        System.exit(3);
      }
      // delete existing database because dropping tables is a bit complicated
      // due to foreign key dependency contstraints
      dbFile.delete();
    }

    final String suffixlessAbsoluteDatabasePath = new File(dbFilepathNoSuffix).getAbsolutePath();
    final LogHog logHog =
        new LogHog(
            new ConnectionProvider() {
              @Override
              public Connection connect() throws SQLException {
                return EmbeddedDatabaseFactory.create(suffixlessAbsoluteDatabasePath);
              }
            });

    logHog.createAndPopulateDb(logFilepath);

    ViewCreator viewCreator = new ViewCreator(suffixlessAbsoluteDatabasePath);
    viewCreator.createThreadView();
    // REQUEST view requires THREAD view
    viewCreator.createRequestView();
    //    viewCreator.createBadRequestView();
    QuickCheck.reportTells(EmbeddedDatabaseFactory.create(suffixlessAbsoluteDatabasePath));
  }
}
