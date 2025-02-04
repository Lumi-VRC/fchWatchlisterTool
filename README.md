# FCH Watchlist Tool

Welcome to **FTAC Community Hub Watchlist Tool**! This open-source Python application allows you to set up a list of users that you would like the program to notify you about if they join your instance.

This program monitors your VRChat log file, updates usernames automatically, and displays events in a user-friendly interface. Pre-built packages (EXE files) for Windows are available for download in the [Releases](https://github.com/Lumi-VRC/fchWatchlisterTool/releases) tab.

Created by "- Lumine -", current co-owner of Furry Talk and Chill.

**!! DEBUG LOGGING MUST BE TURNED ON IN YOUR IN-GAME SETTINGS. !!**

---
![python_IS2vX7Tvde](https://github.com/user-attachments/assets/3512b82a-351c-48e8-aaa5-b5b2ccf35faf)
---
## Table of Contents

- [Overview](#overview)
- [Releases](#releases)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## Overview

**FCH Watchlist Tool** is designed for moderators and enthusiasts who need a reliable, easy-to-use tool to monitor VRChat activity. The application features real-time log monitoring, automatic username updates via the VRChat API, and a clear, organized display of user join events.

---

## Releases

All packaged versions of **FCH Watchlist Tool** are available in the [Releases](https://github.com/Lumi-VRC/fchWatchlisterTool/releases) section of this repository. Each release includes an executable file that bundles all necessary dependencies—so you don't have to install Python or any external libraries!

- **Download the Latest Version:**  
  Visit the [Releases](https://github.com/Lumi-VRC/fchWatchlisterTool/releases) page and download the latest package (e.g., `FCH_Watchlist_Tool_v1.0.exe`).

- **Installation:**  
  Simply run the downloaded executable to launch the application. No additional installation steps are required!

---

## Features

- **Real-time Log Monitoring:**  
  Continuously monitors the VRChat logs directory and updates the display as new entries appear.

- **Automatic Username Updates:**  
  The application queries the VRChat API every 12 hours to ensure that usernames are always up-to-date.

- **User List Management:**  
  The bottom section displays a two‑column list of users and their profile URLs. Easily add or remove users using the built-in interface.

- **Clear Log Display:**  
  Log entries are shown with human-friendly relative timestamps (e.g., “5 minutes ago”) in a scrollable text view.

- **Sound Notifications:**  
  A sound plays when a new log entry is detected, so you never miss an event—provided the sound file is available.

- **Open Source & Customizable:**  
  The source code is fully available, and major formatting areas are well-commented to help you customize the UI.

---

## Installation

### Download the Executable

1. Go to the [Releases](https://github.com/Lumi-VRC/fchWatchlisterTool/releases) tab.
2. Download the latest executable package for Windows.

### Manual Installation (from Source)

If you prefer to run from source:

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/Lumi-VRC/fchWatchlisterTool.git
   cd yourrepo
