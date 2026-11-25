
# Automated Antivirus & System Threat Manager

![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white)
![Matplotlib](https://img.shields.io/badge/Matplotlib-11557C)
![OOP](https://img.shields.io/badge/OOP-Programming-blue)
![Testing](https://img.shields.io/badge/Testing-unittest-2EA44F)

The application simulates an antivirus scanning system that models security threats, calculates risk levels, generates reports, and visualizes scan results.

## Features

- Abstract threat base class
- Ransomware and spyware threat models
- Threat-specific risk calculations
- Danger score validation and encapsulation
- Simulated threat signature generation
- Configurable system risk threshold
- Custom exception handling
- Automatic backup report generation
- Risk and threat visualization using Matplotlib
- Unit testing

## Concepts Practiced

- Object-oriented programming (OOP)
- Abstraction and abstract classes
- Inheritance and polymorphism
- Encapsulation and properties
- Input validation
- Exception handling
- File handling
- Data visualization
- Unit testing

## Project Structure

| File | Purpose |
| --- | --- |
| security_threats.py | Threat models and risk calculations |
| scanning_engine.py | Scan simulation and report generation |
| main.py | Application entry point and visualization |
| test_security.py | Unit tests |
| requirements.txt | Project dependencies |

## Getting Started

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Run the application:

```bash
python3 main.py
```

## Testing

```bash
python3 -m unittest test_security.py
```

## Generated Reports

- `backup_report.txt` — Threat assessment report
- `threat_report.png` — Risk and threat visualization

## Notes

This project is an educational simulation of antivirus risk assessment. It does not detect, execute, or remove real malware.

---

Developed as part of my college Python OOP studies.
