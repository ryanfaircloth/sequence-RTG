## Available flags for sequence_db_main.go

*  **config file:** shorthand: **--config**
   *  description: this is the path to the sequence.toml file. 
   *  valid values are: filename and path to a valid TOML file in the correct format. Defaults to sequence.toml in the same location as the exe. 
*  **input file:** shorthand: **-i**
   * description: file path with the input data including service and message in json or text format.
   * valid values are: any filename and path, or - for the stdin.
*  **output file:** shorthand: **-o**
   * description: path or (part path if multiple output formats) to the output file for the patterns.
   * valid values are: any filename and path, or omit for stdout
*  **patterns file/folder:** shorthand: **-p** 
   * if not using a database, this is the file or folder that contains files with existing patterns in text format.
   * valid values are: any filename, folder and path
*  **input file format:** shorthand: **-k** 
   * description: format of the input data, either as json or a text file with service and message separated by a space.
   * valid values are: json or txt. Defaults to txt
*  **output file format:** shorthand: **-f**
   * description: output formats for patterndb, in xml for direct use or yaml for building with build tool. Text is the default. 
   * valid values are: xml, yaml, txt or a comma separated list of any combination of these values
*  **batch size:** shorthand: **-b** 
   * description: if using stdin, you can set this value to get sequence to wait for x messages before it processes a batch.
   * valid values are: any integer > 0 *NB: only to be used with stdin for now*
*  **log file:** shorthand: **-l** 
   * description: name and location of the log file.
   * valid values are: any filename and path, defaults to sequence.log in the exe location
*  **log level:** shorthand **-n** 
   * description: level of logging detail.
   * valid values are: 'trace' 'debug', 'info', 'error', 'fatal', defaults to 'info'
*  **threshold** shorthand: **-t** 
   * description: used with the purge patterns function to remove patterns from the database with a low match count.
   * valid values are: any int above 0
*  **complexity score** shorthand: **-c** 
   * description: used when outputing the patterns to file, helps to filter out patterns that may be over-tokenised
   * valid values are: any decimal between 0.0 and 1.0, recommended 0.5
*  **out system** shorthand: **-s** 
   * description: Used to output directly to file in correct forma when usedatabase in the config is set to false. 
   * valid values are: patterndb or grok. 
*  **conn** shorthand: **--conn** 
   * description: Connection string for the server/database for creating the new database. 
   * valid values are: valid connection string for the database type chosen. 
*  **type** shorthand: **--type** 
   * description: database type used when creating the new database. 
   * valid values are: sqlite3, mssql, psql, mysql


## Available methods for sequence_db_main.go
*  **createdatabase:** this is for creating a new empty sequence sqlite3 database. 
   * Uses the flag --conn for the new database path/name, --type and --config  
   * NB: It will error if an existing sequence database found at the -conn path for sqlite.
   * If wishing to use another database type, please read the changing the database page.
```
Example: createdatabase --conn [path]/sequence.sdb --type sqlite3 --config [path]/sequence.toml 
```

*  **scan:** this is for processing smaller files of messages < 20 to view how they are tokenised. Useful for debugging if a pattern is not forming well. 
   * Uses the flags -i, -o, -k, --config
```
Example: scan -i [path]/input.txt -k json --config [path]/sequence.toml -o [path]/out-scan.txt 
```

*  **analyze:** this is for processing smaller files of messages < 100,000 from many very similar services. 
   * Uses the flags -i, -k, -p, --config

*  **analyzebyservice:** this is for processing small and large files of messages from many different services. 
   * Uses the flags, --config, -i, -k, -b, -l, and -n. NB: To exit from continuous mode, send the word 'exit' to the stdin
```
Example: analyzebyservice -i - -k json --config [path]/sequence.toml -n debug -b 100,000 -m cont 
```

*  **exportpatterns:** this is for writing the patterns from the database to a file for the syslog_ng pattern db or grok
   * for patterndb, it will append the appropriate extension to the output file eg: out.yaml, out.xml, so the outfile name should have no extension, eg [path]/out
   * for grok it will use the whole file name, so use a complete path eg [path]/out-grok.txt
   * Uses flags --config, -n, -l, -o, -f, -c, -s
```
Example: exportpatterns -o [path]/out -f xml,yaml  -n debug --config [path]/sequence.toml -c 0.5 -s patterndb
```

*  **purgepatterns:** this is for deleting the patterns from the database with a cumulative match count less than the passed threshold.       
   * Uses flags --config, -t
```
Example: purgepatterns -t 5 --config [path]/sequence.toml 
```

*  **updateignorepatterns:** this is for setting the ignore pattern flag on a list of patterns in the database. Once a pattern is marked as ignored, it won't export from the database again. The input file needs to have one patternid per line. The pattern will still be used by the Sequence parser.
   * Uses flags --config, -i
```
Example: updateignorepatterns -i [path]/ignore.txt --config [path]/sequence.toml 
```



