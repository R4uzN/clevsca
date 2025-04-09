# clevsca

**clevsca** is a powerful network scanning tool built with PyQt5. It provides three main functionalities: Web Scan, Directory Scan, and Port Scan. Each of these functionalities runs in separate asynchronous threads to ensure efficient and non-blocking operations.

**Clone the repository**:
```bash
git clone https://github.com/r4uzn/clevsca.git
cd clevsca
```

## Features

- **Web Scan**: Fetches and displays the status code, headers, and cookies of a given URL.
- **Directory Scan**: Scans for directories on a given URL based on predefined wordlists (alpha, numbers, alphanum).
- **Port Scan**: Scans a specified range of ports on a given URL to identify open ports.
- **Save Results**: Allows users to save the scan results to a text file.
- **Reset**: Clears the output area.
- **Info**: Provides additional information about the tool and the author.

## Installation

To run this application, you need to have Python 3.x installed along with the following packages:

- PyQt5
- aiohttp
- requests

You can install the required packages using `pip`:

```bash
pip install PyQt5 aiohttp requests
```
