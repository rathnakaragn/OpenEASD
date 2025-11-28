# OpenEASD

OpenEASD (Open Extended Attack Surface Discovery) is a powerful and flexible platform for discovering and managing your attack surface. It combines multiple security tools to provide a comprehensive view of your assets and potential vulnerabilities.

## Features

*   **Attack Surface Discovery:** Uses tools like Subfinder and Amass to discover subdomains.
*   **Port Scanning:** Uses Nmap and Naabu to identify open ports.
*   **Web Probing:** Uses HTTpx to gather information about web services.
*   **Vulnerability Detection:** An analysis engine to identify potential vulnerabilities.
*   **REST API:** A FastAPI-based API for programmatic access to the data.
*   **Command-Line Interface:** A feature-rich CLI for interacting with the system.
*   **Event Bus:** Asynchronous communication between components.

## Getting Started

### Prerequisites

*   Python 3.10+
*   The external tools used by this project (e.g., subfinder, naabu, nmap, httpx, amass) must be installed and available in your `PATH`.

### Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/your-username/openeasd.git
    cd openeasd
    ```

2.  Install the Python dependencies:
    ```bash
    pip install -r requirements.txt
    ```

### Running the Application

**API Server:**

To run the FastAPI server, use the following command:

```bash
uvicorn src.api.main:app --reload
```

The API will be available at `http://127.0.0.1:8000`.

**Command-Line Interface:**

The CLI is built with Click and can be accessed through `src/cli/main.py`.

Example:
```bash
python src/cli/main.py scan --domain example.com
```

For a full list of commands, run:
```bash
python src/cli/main.py --help
```
