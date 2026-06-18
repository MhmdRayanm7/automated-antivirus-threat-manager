# Automated Antivirus & System Threat Manager

A simple Python project that simulates an antivirus threat scanner.

The project uses object-oriented programming to create different virus types, scan them, calculate risk, write a backup report, run tests, and show basic charts.

## Features

* Abstract base class
* Ransomware and spyware classes
* Encapsulation with private danger score
* Risk calculation
* Custom exception for high system risk
* Backup report file
* Unit tests
* Simple threat charts with matplotlib

## Project Files

```text
security_threats.py
scanning_engine.py
main.py
test_security.py
requirements.txt
README.md
.gitignore
```

## File Description

### security_threats.py

Contains the threat classes:

* `Threat`
* `RansomwareVirus`
* `SpywareVirus`

This file handles the virus data, danger score, risk calculation, and threat signatures.

### scanning_engine.py

Contains:

* `ScanningEngine`
* `SystemCompromisedError`

This file scans the threats, calculates total risk, saves signatures, and writes a backup report.

### main.py

Runs the project.

It creates sample threats, scans them, prints the results, and shows charts.

### test_security.py

Contains unit tests for the project.

The tests check danger score validation, private field protection, risk calculation, and custom exception handling.

## Install Requirements

```bash
pip install -r requirements.txt
```

## Run the Project

```bash
python main.py
```

## Run Tests

```bash
python -m unittest test_security.py
```

Expected result:

```text
OK
```

## Generated Files

The program may create these files:

```text
backup_report.txt
threat_report.png
```

These files are generated automatically and should not be uploaded to GitHub.

## Git Ignore

The `.gitignore` file should include:

```gitignore
.venv/
__pycache__/
*.pyc
.idea/
backup_report.txt
threat_report.png
```

## Example Output

```text
Scan finished successfully.
Total risk: 371.5

Generated signatures:
- RANSOM-locker.exe-500
- RANSOM-photo_encryptor.exe-250
- SPY-keylogger.exe-passwords
- SPY-cookie_reader.exe-browser cookies
```

## Project Goal

The goal of this project is to practice Python OOP, inheritance, encapsulation, exceptions, unit testing, and simple visualization.
