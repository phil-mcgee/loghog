/* (C)2024 */
package com.contrastsecurity.agent.loghog.sql;

import java.util.List;

public interface SqlTable {
  String name();

  List<String> columnNames();
  // FIXME Do we need it?   List<Class<?>> columnTypes();
}
