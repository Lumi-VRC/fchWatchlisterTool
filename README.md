This program:
- Reads through all of and then watches your latest log file located in %APPDATA%/LocalLow/VRChat/VRChat/ on a different thread.
- Filters it for entries containing "OnPlayerJoined".
- Compares it to keywords found in local file users.txt (editable in-app)
- Does some string manipulation to get the timestamp of each matching entry.
- Displays matched usernames with their corresponding timestamps.
- Optionally plays a sound when a watchlisted user joins your lobby.
