/* (C)2024 */
package com.contrastsecurity.agent.loghog;

import com.contrastsecurity.agent.loghog.db.EmbeddedDatabaseFactory;
import com.contrastsecurity.agent.loghog.db.LogDatabaseUtil;
import com.contrastsecurity.agent.loghog.logshreds.MesgShred;
import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;

public class Loghog {

  public static void createAndPopulateDb(
      final String logFilepath, final String dbFilepathNoSuffix) {
    try (final Connection connection = EmbeddedDatabaseFactory.create(dbFilepathNoSuffix)) {
      LogDatabaseUtil.initializeLogTable(connection, logFilepath);
      new MesgShred().createAndPopulateShredTables(connection);
      //            new LmclShred().createTables(connection);
      //            new AcelShred().createTables(connection);
      //            new AmqpShred().createTables(connection);
      //            new CrumbShred().createTables(connection);
    } catch (SQLException | IOException e) {
      e.printStackTrace();
    }
  }

  public static void main(String[] args) {
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
    createAndPopulateDb(logFilepath, dbFilepathNoSuffix);
  }
}
