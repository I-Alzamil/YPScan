# Your Powerful Scanner (YPScan)

<p align="center">
    <img src="assets/icon.ico" width="200" alt="YPScan">
</p>

YARA and IOC scanner that is built on rust. Scanner was inspired from [Loki](https://github.com/Neo23x0/Loki) scanner retaining the following features from it:

* Load and scan using Yara rules.
* Load and scan using hashes in MD5, SHA1, and SHA256.
* Exclude paths using regex
* Exclude hashes

as well as the following additional features:

* Progress tracking
* Encrypt Yara rule files and hashes to avoid false positive AV detection when mass deploying the scanner.
* Detect and display digital signature information for PE files in Windows.
* Multi-threaded scan for a faster scan.
* Ability to scan with no file size limit (check [no size limit](#Scanning-with-no-file-size-limit) section for more information).
* Both csv and json support in both console and file output.
* Ability to encode in ANSI for Windows to solve some encoding issues when piping output to collection agents or programs in non-English versions of Windows.
* Ability to run using the new [YARA-X](https://github.com/VirusTotal/yara-x) engine (Needs to be compiled using yara_x feature to use it).

## Usage

Scan subcommand:

    starts a file scan, by default scan all drives with 100 MB size limit and uses 1/2 CPUs

    Usage: YPScan.exe scan [OPTIONS]

    Options:
      -a, --all-drives            Scan all drives including removable (in windows only)
      -r, --all-reasons           Display all match reasons instead of only 4
      -p, --path <PATH>           Path to be scanned instead of all fixed drives
      -n, --no-size               Removes file size limit. Increased RAM usage possible depending on yara rules.
      -s, --size <NUMBER>         Max size filter (in KB) to ignore large files in scan
      -t, --threads <NUMBER>      Number of threads to use in scan
      -P, --power                 Power scan mode, uses all avaliable cpu
      -q, --no-progress           Disable progress display and tracking
      -y, --yara-path <PATH>      Path to yara rule files (defaults to yara next to the executable)
      -i, --iocs-path <PATH>      Path to iocs files (defaults to iocs next to the executable)
      -c, --config-path <PATH>    Path to config files (defaults to config next to the executable)
          --only-alerts           Filter output level to alerts and higher
          --no-color              Switch off console color
          --no-output             Switch off console output
          --csv-output            Change console logging to csv
          --json-output           Change console logging to json
          --file-name <FILENAME>  Sets a custom filename to the log file
          --no-log                Switch off file output
          --csv-log               Change log file format to csv
          --json-log              Change log file format to json
          --syslog <CONNECTION>   Enable logging to syslog (format: udp://192.168.1.5:514)
          --ansi-encoding         Enable encoding using windows ansi pages, only works in non tty
      -d, --debug                 Enable more informative logging for debugging
      -v, --trace                 Enable extream logging for debugging
      -h, --help                  Print help
      -V, --version               Print version

Encrypt/Decrypt subcommand:

    encrypts yara file in order to avoid false positive AV detections

    Usage: YPScan.exe encrypt [OPTIONS] [FILE]

    Arguments:
      [FILE]  Path to file to be encrypted

    Options:
      -o, --output-path <PATH>    Path to output encrypted files
          --only-alerts           Filter output level to alerts and higher
          --no-color              Switch off console color
          --no-output             Switch off console output
          --csv-output            Change console logging to csv
          --json-output           Change console logging to json
          --file-name <FILENAME>  Sets a custom filename to the log file
          --no-log                Switch off file output
          --csv-log               Change log file format to csv
          --json-log              Change log file format to json
          --syslog <CONNECTION>   Enable logging to syslog (format: udp://192.168.1.5:514)
          --ansi-encoding         Enable encoding using windows ansi pages, only works in non tty
      -d, --debug                 Enable more informative logging for debugging
      -v, --trace                 Enable extream logging for debugging
      -h, --help                  Print help
      -V, --version               Print version

## Signature files

There are already many already established repositories when it comes to yara rules and iocs, examples can be found in [signature-base](https://github.com/Neo23x0/signature-base) and [reversinglabs-yara-rules](https://github.com/reversinglabs/reversinglabs-yara-rules). However, you have to copy files to their correct folders in the tool own structure (.txt files must be converted to .ioc for hashes). An updater tool is planned to grap the lastest rules and iocs and make this process easier.

Note: Release downloads already have YARA and IOCS packaged and updated at the time of release.

## Scanning with no file size limit

This scanner allows users to disabled file size limit with -n or --no-size which might result in higher RAM usage. However, the tool was heavily tested when it comes to scanning large files and optimizations went to improve that process as much as possible.
Due to how the scanner is built many components are in play here:

* File hasher is optimized well and doesn't use any RAM when hashing large files due to read buffering.
* Yara scanner uses [YARA](https://github.com/VirusTotal/yara) or [YARA-X](https://github.com/VirusTotal/yara-x) engine and depending on the type of rules used, RAM usage will vary.
* All other components are optimized and tested and doesn't use that much RAM no matter the file size.

To summarize, the type of Yara rules loaded will determine how much RAM the scanner is going to use when it comes to scanning single large files.

## Building

The scanner can be built using one of two features:

* Building with [YARA](https://github.com/VirusTotal/yara) engine (Default).
* Building with [YARA-X](https://github.com/VirusTotal/yara-x) engine.

In order to build with default feature all you need to do is to run build with cargo in release mode:

    cargo build --release

if you want to build with YARA-X engine you should run the following:

    cargo build --release --features "yara_x" --no-default-features

### Windows environment

Windows development environment needs to have [openssl](https://github.com/openssl/openssl), [LLVM](https://github.com/llvm/llvm-project), and [YARA](https://github.com/VirusTotal/yara) (if using yara_c feature).

LLVM can easily be installed with winget:

    winget install --id=LLVM.LLVM -e

Easiest way to get both openssl and yara is using [vcpkg](https://github.com/microsoft/vcpkg) by running the following install command:

    vcpkg.exe install yara:x64-windows-static

After running the command you should find "packages" directory inside vcpkg housing both openssl and yara.

Using "Edit system environment variables" from windows control panel, add the following variables:

* LIBCLANG_PATH: C:\Program Files\LLVM\lib
* OPENSSL_DIR: [vcpkg openssl package path]
* YARA_CRYPTO_LIB: OpenSSL
* YARA_INCLUDE_DIR: [vcpkg yara package path\\include]
* YARA_LIBRARY_PATH: [vcpkg yara package path\\lib]
* YARA_OPENSSL_DIR: [vcpkg openssl package path]

## TO BE DONE

- [ ] Add an updater function in order to get up-to-date yara and iocs from open source repositories.
- [ ] Add ability to scan processes.
- [ ] Add more static analysis features.

## Credit

+ Special thanks to [Neo23x0 (Florian Roth)](https://github.com/Neo23x0) for his inspiration, which led to creating this project.
+ Special thanks to the [VirusTotal team](https://github.com/VirusTotal) for their YARA engine.
+ Special thanks to crate owners whose crates are used in this project, which can be found in the cargo.toml file.