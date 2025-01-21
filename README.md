# Log Analyzer Tool

The Log Analyzer Tool is a Python-based application designed to help you analyze log files for suspicious activities such as malware, unauthorized access, phishing attempts, file tampering, security breaches and more. The tool works on macOS, Windows, and Linux. It features a user-friendly GUI and generates clear reports with graphs for easy interpretation.

## Features

- Analyze log files for various suspicious activities.
- Provides recommended actions for detected issues.
- Allows adding new patterns and corresponding remedies.
- Generates a graphical visualization of detected issues.
- Easy-to-use graphical user interface for selecting log files and running scans.

## Requirements

- Python 3.x
- Required Python libraries:
  - `matplotlib`
  - `tkinter` (macOS and Linux only)
  - `numpy`
- Virtual environment (recommended)

## Installation

### Clone the repository:

    git clone https://github.com/touseefahmed96/Log_analyzer.git
    cd Log_analyzer
    
### For macOS and Linux

1. Ensure Python 3.x is installed. If not, install it:

    ```bash
    sudo apt-get install python3 python3-pip   # For Debian-based systems
    sudo pacman -S python python-pip          # For Arch-based systems
    brew install python                       # For macOS using Homebrew
    ```
2. Create a Virtual Environment:

    ```bash
    For Linux/Macos:

    python3 -m venv venv
    source venv/bin/activate 
    ```
2. Install the required libraries:

    ```bash
    pip3 install -r requirements.txt
    ```

3. If `tkinter` is not installed, install it via this command:

    ```bash
    sudo apt-get install python3-tk           # For Debian-based systems
    sudo pacman -S tk                         # For Arch-based systems
    ```

### For Windows

1. Ensure Python 3.x is installed. If not, download and install it from the [official website](https://www.python.org/downloads/).

2. Create a Virtual Environment:
    ```bash
    For Windows: 

    python3 -m venv venv
    venv\Scripts\activate 
    ``` 
3. Install the required libraries:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. Run the application:

    ```bash
    For Linux/Macos:
    sudo python log_analyzer.py

    For Windows: 
    python log_analyzer.py
    ```

2. Using the GUI:
- Click on "Select Log File and Scan" to choose a log file.
- The analysis results will be displayed, including any detected suspicious activities and their remedies.
- The output report and graph will be saved in the same directory as the log file.
