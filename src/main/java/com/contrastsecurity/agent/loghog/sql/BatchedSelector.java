package com.contrastsecurity.agent.loghog.sql;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class BatchedSelector implements AutoCloseable {

    final int batchSize;
    final String selectSql;
    Connection connection;
    PreparedStatement statement;
    ResultSet resultSet;

    private BatchedSelector(final Connection connection, final String selectSql, int batchSize) {
        if (connection == null) throw new NullPointerException("connection == null");
        if (selectSql == null) throw new NullPointerException("selectSql == null");
        if (batchSize <= 0) throw new IllegalArgumentException("batchSize <= 0");
        this.connection = connection;
        this.selectSql = selectSql;
        this.batchSize = batchSize;

    }

    public static BatchedSelector open(final Connection connection, final String selectSql, int batchSize) throws SQLException {
        return new BatchedSelector(connection, selectSql, batchSize).prepare();
    }

    public List<Object[]> nextBatch() throws SQLException {
        if (statement == null) {
            return null;
        }
        if (resultSet == null) resultSet = connection.prepareStatement(selectSql).executeQuery();
        int nColumns = resultSet.getMetaData().getColumnCount()
        List<Object[]> returned = new ArrayList<>(batchSize);
        for (int row = 0; row < batchSize; row++) {
            if (!resultSet.next()) {
                close();
                break;
            }
            Object[] rowResult = new Object[nColumns];
            for (int i = 1; i <= nColumns; i++) {
                rowResult[i-1] = resultSet.getObject(i);
            }
            returned.add(rowResult);
        }

        return returned;
    }

    public void close() {
        if (resultSet != null) {
            try {
                resultSet.close();
            } catch (SQLException e) {
            }
        }
        if (statement != null) {
            try {
                statement.close();
            } catch (SQLException e) {
            }
        }
        connection = null;
    }

    private BatchedSelector prepare() throws SQLException {
        statement = connection.prepareStatement(selectSql);
        statement.setFetchSize(batchSize);
        return this;
    }
}
