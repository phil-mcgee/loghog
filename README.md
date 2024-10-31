# Loghog

A Java project that parses Java Agent logs into an embdded SQL database to allow searching and extracting interesting data using SQL.

### Dependencies

This project is intended to be build and run using JDK 21 or newer.

### Building

```shell
./gradlew build
```

Uses `Spotless` for formatting:

```shell
./gradlew spotlessApply
```

### Running loghog to create the database

```shell
java -jar build/libs/loghog-all.jar ~/logs/somelog.err
```

Will produce an H2 embedded database as a sibling file to the parsed log and with the same name but with file type `.mv.db`.
```shell
√ ~/logs % ls -l                                                                                                         15:55:30
total 63024
-rw-r--r--  1 philmcgee  staff  18870272 Oct 29 15:52 somelog.mv.db
-rw-rw-r--@ 1 philmcgee  staff  12456324 Oct 28 14:36 somelog.err
```

### Querying the database

There are various tools that can work with the H2 database file.  I've been using `dbeaver`, https://dbeaver.io/, which is an Eclipse
based GUI database management tool.

It can be installed with Homebrew:

```shell
brew install –cask dbeaver-community
```

You'll need to install an H2 JDBC driver.  The default installation (supposed to pull from Maven) didn't work for me.
I blame Netskope based on zero evidence. I manually downloaded the H2 jar, h2-2.1.210.jar, and
for the H2 connection settings selected `Driver settings`, opened the Libraries tab, and replaced the
two existing entries with the file path to my downloaded H2 JAR.

It's slightly fiddly.  Ask me for help if you need it.

Once the driver is installed you "connect" to the H2 database by selecting the `db.mv.db` file
you're interested in.
