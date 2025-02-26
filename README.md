# FCH Watchlist Tool

Welcome to **FTAC Community Hub Watchlist Tool**! This open-source Python application allows you to set up a list of users that you would like the program to notify you about if they join your instance. It also displays your recent join history with them, to help you build a profile!

This program monitors your VRChat log file, updates usernames automatically, and displays events in a user-friendly interface. Pre-built packages (EXE files) for Windows are available for download in the [Releases](https://github.com/Lumi-VRC/fchWatchlisterTool/releases) tab.

Created by "- Lumine -", current co-owner of Furry Talk and Chill.

**!! DEBUG LOGGING MUST BE TURNED ON IN YOUR IN-GAME SETTINGS. !!**

**!! DEBUG LOGGING MUST BE TURNED ON IN YOUR IN-GAME SETTINGS. !!**

**!! DEBUG LOGGING MUST BE TURNED ON IN YOUR IN-GAME SETTINGS. !!**


  Add users by pasting in the users Username and Profile Link from the VRChat Website!
  Alternatively, click the History button to see users who previously joined you and select "add" to add them to your watchlist!


---
<img width="590" alt="image" src="https://github.com/user-attachments/assets/b371c287-9b1e-4b82-a92c-5196d673c509" />


![devenv_kkPr2Xzn31](https://github.com/user-attachments/assets/b73461f5-03ab-4207-a30c-220f0ba4d426)


---
## Table of Contents

- [Overview](#overview)
- [Releases](#releases)
- [Features](#features)
- [Installation](#installation)

---

## Overview

The **FCH Watchlist Tool** is designed for moderators who would like to build 'problem user' lists for themselves to enhance their ability to protect their community.

This program takes a user-inputted list of users and profile links, and scans the users latest log file for OnJoined events, notifying the user if any new ones pop up with the included sound.mp3 + text notification.

It requires a login in order to access VRChat's API to update peoples names if they try to change them. Your login information is stored in plaintext in %APPDATA% and is not shared, feel free to pop the source code into a GPT or read it yourself.

If you scan with VirusTotal, it will flag from 1-2 providers due to the lack of a .dll certificate. I'm not paying for one, since this program is open source.

The tool also allows you to view people who were recently in your instance in order to quickly add them to your watchlist.

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
  This is done by logging into the app. Your login is stored locally at %APPDATA%/Roaming/FCHWatchlistTool, along with your user list and session cookies.

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

