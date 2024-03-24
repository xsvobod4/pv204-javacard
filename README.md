# JavaCard Project - PV204

### Team:
- Svoboda Martin, 553631 (xsvobod4, Mitt33)
- Ondrej Chudacek, 544028 (SPXcz)
- Vladimir Penaz, 485278 (vladimir-penaz)

This is implementation of project *JavaCard secret storage* to subject PV204 Security Technologies at Masaryk University.
The basis of the project is template available at [crocs-muni/javacard-gradle-template-edu]

Project contains two modules:

- `applet`: contains the javacard applet. Can be used both for testing and building CAP
- `main`: contains Java applications to communicate with applet via [JCardSim] or with real card

Repository features:
 - Build (CLI / IntelliJ Idea)
 - Build CAP for applets
 - Test applet code in [JCardSim] / physical cards

Applet functionality:
- Store secrets on card
- Get list of names of stored secrets
- Get value of stored secret
- PIN verification & PIN change
- (TODO:) Secure Channel communication 
 
## How to use

### Clone 
- with HTTPS:
```
git clone --recursive https://github.com/xsvobod4/pv204-javacard.git
```

- Clone with SSH
```
git clone --recursive git@github.com:xsvobod4/pv204-javacard.git
```

### Build
- build CAP, JAR file and run tests with:
```bash
./gradlew buildJavaCard --info --rerun-tasks
```



### Run
- Run with gradle wrapper `./gradlew` on Unix-like system or `./gradlew.bat` on Windows
  to build the project for the first time (Gradle will be downloaded if not installed).
    ```
    ./gradlew run --args="-h"
    ```

- Or run with `applet-1.0-SNAPSHOT.jar` generated in `applet/build/libs`
    ```
    java -jar applet-1.0-SNAPSHOT.jar -h
    ```

- Output of help command prints all app functionality options:
 
```
  ./gradlew run --args="[-h | --help] -c <card type> [-t <terminal number>] -i <instruction> [instruction_options]"
```
Instruction options:
- `-p`, `--pin <pin>`: Four-digit card PIN. **Default PIN is 1234**
- `-n`, `--new_pin <pin>`: New four-digit PIN for PIN change.
- `-k`, `--key <key>`: Query data key. Should be a number 1-15 or the name of the slot.
- `-v`, `--value <value>`: Query data value of length <= 64.
- `-o`, `--overwrite`: Overwrite existing data on card.

Card types:
- `sim`: Simulated card.
- `real`: Real card.

Instructions:
- `change_pin`, `cp`: PIN change. Options: `-p <old pin>` `-n <new pin>`.
- `get_secret_names`, `sn`: Get secret names.
- `reveal_secret`, `rs`: Reveal secret. Options: `-p <pin>` `-k <key>`.
- `set_secret`, `set`: Set secret. Options: `-p <pin>` `-k <key>` `-v <value>` `[-o]`

### Running tests

```
./gradlew clean build
```

### Supported Java versions

Java 8-u271 is the minimal version supported. 

Make sure you have up to date java version (`-u` version) as older java 8 versions
have problems with recognizing some certificates as valid.

Only some Java versions are supported by the JavaCard SDKs.
Check the following compatibility table for more info: 
https://github.com/martinpaljak/ant-javacard/wiki/Version-compatibility



[JCardSim]: https://jcardsim.org/
[ant-javacard]: https://github.com/martinpaljak/ant-javacard
[oracle_javacard_sdks]: https://github.com/martinpaljak/oracle_javacard_sdks
[crocs-muni/javacard-gradle-template-edu]: https://github.com/crocs-muni/javacard-gradle-template-edu

