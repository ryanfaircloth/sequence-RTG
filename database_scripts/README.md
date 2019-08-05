The database library used with this project is SQL Boiler. Its documentation can be found [here](url:https://github.com/volatiletech/sqlboiler) for an up to date list of supported databases. 

## SQLite3

If you want to use SQLite3, the great news is you can do nothing as sequence uses this by default. You can use the create database command to create the database and then update the sequence.toml file with the path to your database and you should be set to go.

### To build the models for SQLite3
```
#for SQLite3
go get github.com/volatiletech/sqlboiler
go get github.com/volatiletech/sqlboiler-sqlite3

```
Build both projects and copy the exe files to the Go bin folder. In the Sequence folder configure the sqlboiler.toml to use your sequence database. From the Sequence directory run sqlboiler sqlite3 --wipe to regenerate the models.

## Microsoft SQL Server 

Firstly download the driver and support libraries for the database.

```
#for MSSQLServer 2012+
go get github.com/volatiletech/sqlboiler
go get github.com/volatiletech/sqlboiler/drivers/sqlboiler-mssql
go get github.com/denisenkom/go-mssqldb

```
In the databasehandler.go file, replace the reference for the sqlite3 library with the go-mssqldb library

```
_ "github.com/denisenkom/go-mssqldb"

```

To create the database the best approach is to use the database script in the folder database-scripts/mssql.txt directly in SQL Server Management Studio, first replacing %path% with the path to the db files and %databasename% with the name of the database, or to do a similar thing from a build server.

The createdatabase function can also be used as shown below, but I keep running into permission issues saving the files and I am not sure if it a limitation of working with the Microsoft Browser service or local to my computer. 

```
createdatabase --type mssql --conn sqlserver://username:password@host/instance?database=master&sslmode=disable -d C:\databases\ --name Sequence

```

In the sequence.toml file update the databasetype to mssql and the connectioninfo for your database,
replacing the username, password, host and instance names below.

```
connectioninfo = "sqlserver://username:password@host/instance?database=Sequence&sslmode=disable"
databasetype = "mssql"

```

Once the database has been built, the next step is to rebuild the models. 

The first step to do this is to navigate to github.com/volatiletech/sqlboiler and run go build. Do the same for github.com/volatiletech/sqlboiler/drivers/sqlboiler-mssql.

In the sqlboiler.toml file in the sequence folder, update the [mssql] section to match your SQL server, users and database.

For the command line, navigate to the sequence folder and execute sqlboiler mssql --wipe. This will rebuild the models. It should find the built sqlboiler.exe files from above, however if not, you can copy them into the sequence folder from the Go bin folder.

Once the models are rebuilt, and the connection info updated in the sequence.toml file. Everything should work with your new database.

## PostgreSQL

Firstly download the driver and support libraries for the database.

```
#for PostgreSQL
go get github.com/volatiletech/sqlboiler
go get github.com/volatiletech/sqlboiler/drivers/sqlboiler-psql
go get github.com/lib/pq

```
In the databasehandler.go file, replace the reference for the sqlite3 library with the postgres library

```
_ "github.com/lib/pq"

``` 

In the sequence.toml file update the databasetype to postgres and the connectioninfo for your database,
replacing the username, password, host and instance names below.

```
connectioninfo = "dbname=Sequence host=localhost user=postgres password=test sslmode=disable"
databasetype = "postgres"

```
In the database_scripts folder, locate the postgres.txt file and use this script to create the database and tables.
Once the database has been built, the next step is to rebuild the models in the code for the new format.

The first step to do this is to navigate to github.com/volatiletech/sqlboiler and run go build. Do the same for github.com/volatiletech/sqlboiler/drivers/sqlboiler-psql. Copy the exe files into the Go bin folder or the sequence folder.

In the sqlboiler.toml file in the sequence folder, update the [psql] section to match your Postgres server, user details and database.

From the command line, navigate to the sequence folder and execute sqlboiler psql --wipe. This will rebuild the models. It should find the built sqlboiler.exe files from above.

Build the sequence module and you are all set to save data into your new database.

Once the models are rebuilt, and the connection info updated in the sequence.toml file. Everything should work with your new database.

## MySQL

Firstly download the driver and support libraries for the database.

```
#for MySQL
go get github.com/volatiletech/sqlboiler
go get github.com/volatiletech/sqlboiler/drivers/sqlboiler-mysql
go get github.com/denisenkom/go-mssqldb
go get github.com/go-sql-driver/mysql

```
In the databasehandler.go file, replace the reference for the sqlite3 library with the mysql library

```
_ "github.com/go-sql-driver/mysql"

```

In the sequence.toml file update the databasetype to mysql and the connection info for your database,
replacing the user, password, and database names below.

```
connectioninfo = "user:password@/database"
databasetype = "mysql"

```
Using the script called mysql.txt in the database_scripts folder, create the database and tables.
Once the database has been built, the next step is to rebuild the models. 

The first step to do this is to navigate to github.com/volatiletech/sqlboiler and run go build. Do the same for github.com/volatiletech/sqlboiler/drivers/sqlboiler-mysql. Copy the exe files into the Go bin folder or the sequence folder.

In the sqlboiler.toml file in the sequence folder, update the [psql] section to match your MySQL server, user details and database.

From the command line, navigate to the sequence folder and execute sqlboiler psql --wipe. This will rebuild the models. It should find the built sqlboiler.exe files from above.

Build the sequence module and you are all set to save data into your new database. **Note:** When I tested this the PatternExamples slice was renamed in the model generation to just Examples. If this is the case you will need to update the usages of PatternExamples or your models.

Once the models are rebuilt, and the connection info updated in the sequence.toml file. Everything should work with your new database.
