# Automated Antivirus & System Threat Manager

A Python object-oriented programming project that simulates a simple antivirus scanning engine and system threat manager.

The project creates malware threat objects, calculates their risk levels, scans them with an antivirus engine, handles high-risk system warnings, writes a backup report, runs unit tests, and displays threat analytics using charts.

## Project Objective

The goal of this project is to practice:

* Object-oriented programming
* Abstract classes
* Inheritance
* Polymorphism
* Encapsulation
* Python properties
* Custom exception handling
* Unit testing
* Basic data visualization

## Features

* Abstract base class using `abc.ABC`
* Base threat class named `Threat`
* Concrete threat classes:

  * `RansomwareVirus`
  * `SpywareVirus`
* Private danger score field using `__danger_score`
* Controlled score access using `@property`
* Input validation with `ValueError`
* Custom exception named `SystemCompromisedError`
* Scanning engine that calculates total system risk
* Threat signature generation
* Backup report generation
* Unit tests using `unittest`
* Threat charts using `matplotlib`

## Project Structure

```text
automated-antivirus-threat-manager/
│
├── security_threats.py
├── scanning_engine.py
├── main.py
├── test_security.py
├── requirements.txt
├── .gitignore
└── README.md
```

## File Descriptions

### `security_threats.py`

This file contains the threat classes.

Classes included:

* `Threat`
* `RansomwareVirus`
* `SpywareVirus`

The `Threat` class is an abstract base class. It stores the shared data for all threats, such as the file name, file size, and danger score.

The `RansomwareVirus` class represents a ransomware threat. It increases risk when the target directory is a sensitive system directory.

The `SpywareVirus` class represents a spyware threat. It increases risk when it targets sensitive data or has network access.

### `scanning_engine.py`

This file contains the antivirus scanning engine.

Classes included:

* `ScanningEngine`
* `SystemCompromisedError`

The scanning engine stores threats, scans them, calculates total risk, saves generated signatures, and writes a backup report.

If the total risk becomes higher than the allowed risk limit, the engine raises `SystemCompromisedError`.

### `main.py`

This file runs the project demo.

It creates sample threats, adds them to the scanning engine, runs the scan, prints the result, and displays charts.

### `test_security.py`

This file contains unit tests for the system.

The tests check:

* Valid danger score updates
* Out-of-range danger score errors
* Private danger score protection
* Ransomware risk calculation
* Spyware risk calculation
* Scanning engine total risk
* Custom exception behavior

## How to Run

```bash
pip install -r requirements.txt
python main.py
```

## How to Run Tests

```bash
python -m unittest test_security.py
```

Expected result:

```text
OK
```

## Generated Files

When the project runs, it can generate:

```text
backup_report.txt
threat_report.png
```

These files are output files and should be ignored by Git.
