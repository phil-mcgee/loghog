package com.contrastsecurity.agent.loghog.derived;

import com.contrastsecurity.agent.loghog.db.EmbeddedDatabaseFactory;

import java.sql.Connection;
import java.sql.SQLException;

public class ThreadOrdered {
    final String dbPath;

    public ThreadOrdered(final String dbPath) {
        this.dbPath = dbPath;
    }


    void appendThreadNextPrevious() throws SQLException {
        try (Connection connect = EmbeddedDatabaseFactory.create(dbPath)) {
        }
        System.out.println("Request view created.");
    }
}
