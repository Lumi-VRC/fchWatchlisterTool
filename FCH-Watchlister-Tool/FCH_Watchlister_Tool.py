#📦 Imports and Logging Setup
#region
import os
import re
import requests
import queue
import json
import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import time
import threading
from datetime import datetime
from playsound import playsound
import logging

# Setup logging configuration 📝
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
#endregion

#🔧 Global Variables and Data Storage Paths
#region
# Global stop event for threads (used to gracefully exit background threads) 🚦
stop_event = threading.Event()

# Determine the directory for storing user data in APPDATA so that it remains writable
data_dir = os.path.join(os.getenv("APPDATA"), "FCHWatchlistTool")
if not os.path.exists(data_dir):
    os.makedirs(data_dir)
    logging.debug("Created data directory at: " + data_dir)

# VRChat logs directory remains unchanged
appdata_local_low = os.path.join(os.getenv('APPDATA').replace('Roaming', 'LocalLow'), 'VRChat', 'VRChat')
directory = appdata_local_low  # This is the VRChat logs directory

base_dir = os.path.dirname(os.path.abspath(__file__))
# Store user-editable data in the dedicated data directory in APPDATA
settings_path = os.path.join(data_dir, "settings.json")
users_file = os.path.join(data_dir, "users.json")
cookies_path = os.path.join(data_dir, "session_cookies.json")
login_path = os.path.join(data_dir, "login.json")
# Sound file remains in the base directory (read-only resource)
sound = os.path.join(base_dir, "sound.mp3")
#endregion

#🔧 Settings and Login Functions
#region
def load_settings():
    # Loads settings from settings.json, removing sensitive keys if present 🔒
    if os.path.exists(settings_path):
        with open(settings_path, 'r', encoding='utf-8') as file:
            settings = json.load(file)
    else:
        return {}
    keys_to_remove = ["vrchat_username", "vrchat_password"]
    modified = False
    for key in keys_to_remove:
        if key in settings:
            del settings[key]
            modified = True
    if modified:
        with open(settings_path, 'w', encoding='utf-8') as file:
            json.dump(settings, file, indent=4)
    return settings

settings = load_settings()
is_muted = settings.get("is_muted", False)  # Mute setting (True means sound is off) 🎧

def save_settings(data):
    # Saves settings to settings.json, ensuring sensitive keys are removed 🚫🔑
    data.pop("vrchat_username", None)
    data.pop("vrchat_password", None)
    with open(settings_path, "w", encoding='utf-8') as file:
        json.dump(data, file, indent=4)

def load_login():
    # Loads login credentials from login.json 🗝️
    if os.path.exists(login_path):
        with open(login_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    return {}

def save_login(username, password):
    # Saves login credentials (sensitive data) to login.json 🔐
    credentials = {"vrchat_username": username, "vrchat_password": password}
    with open(login_path, "w", encoding='utf-8') as file:
        json.dump(credentials, file, indent=4)

def read_mute_state():
    # Reloads settings and returns the current mute state (True means muted) 🔇
    settings = load_settings()
    return settings.get("is_muted", False)

def write_mute_state(state):
    # Writes the mute state back to settings.json 💾
    settings = load_settings()
    settings["is_muted"] = state
    with open(settings_path, "w", encoding='utf-8') as file:
        json.dump(settings, file, indent=4)
    logging.debug(f"Updated is_muted to {state} in settings.json")

def toggle_mute():
    # Toggles the mute state when the user clicks the mute button 🔄
    global is_muted
    is_muted = not is_muted
    mute_button.config(text="Unmute" if is_muted else "Mute")
    write_mute_state(is_muted)
#endregion

#🔑 VRChat Authentication and Cookie Functions
#region    
otp_queue = queue.Queue()

def prompt_otp(title, message, callback):
    # Prompts the user for an OTP (One-Time Password) if required by VRChat 2FA 🔐
    def ask_otp():
        otp = simpledialog.askstring(title, message, parent=root)
        if otp:
            root.after(0, lambda: callback(otp))
    root.after(0, ask_otp)

def authenticate_vrchat():
    # Attempts to authenticate using saved credentials; if not present, prompts the user 🛡️
    credentials = load_login()
    vrchat_username = credentials.get('vrchat_username', None)
    vrchat_password = credentials.get('vrchat_password', None)
    def ask_for_login():
        nonlocal vrchat_username, vrchat_password
        vrchat_username = simpledialog.askstring("Login Required", "Enter your VRChat username/email:", parent=root)
        vrchat_password = simpledialog.askstring("Login Required", "Enter your VRChat password:", show='*', parent=root)
        if vrchat_username and vrchat_password:
            save_login(vrchat_username, vrchat_password)
        root.after(0, lambda: authenticate_vrchat_continue(vrchat_username, vrchat_password))
    if not vrchat_username or not vrchat_password:
        root.after(0, ask_for_login)
        return None
    return authenticate_vrchat_continue(vrchat_username, vrchat_password)

def authenticate_vrchat_continue(vrchat_username, vrchat_password):
    # Continues authentication with VRChat's API; handles 2FA if necessary 🔑
    login_url = "https://api.vrchat.cloud/api/1/auth/user"
    headers = {'User-Agent': 'FCHWatchlister/1.0 (ftacmoderation@gmail.com)'}
    try:
        response = requests.get(login_url, auth=(vrchat_username, vrchat_password), headers=headers)
        logging.debug(f"Initial login response: {response.status_code}")
        if response.status_code == 200:
            auth_data = response.json()
            cookies = response.cookies
            if 'requiresTwoFactorAuth' in auth_data:
                if 'totp' in auth_data['requiresTwoFactorAuth']:
                    def handle_totp(totp):
                        verify_2fa_url = "https://api.vrchat.cloud/api/1/auth/twofactorauth/totp/verify"
                        otp_data = {"code": totp, "method": "totp"}
                        otp_response = requests.post(verify_2fa_url, json=otp_data, cookies=cookies, headers=headers)
                        logging.debug(f"TOTP verification response: {otp_response.status_code}")
                        if otp_response.status_code == 200:
                            combined_cookies = requests.cookies.RequestsCookieJar()
                            combined_cookies.update(response.cookies)
                            combined_cookies.update(otp_response.cookies)
                            save_cookies(combined_cookies)
                            logging.debug(f"Successfully authenticated with TOTP: {combined_cookies.get_dict()}")
                            root.after(0, start_username_update_thread)
                        else:
                            root.after(0, lambda: messagebox.showerror("2FA Failed", "Failed to verify TOTP"))
                    prompt_otp("2FA Required", "Enter the TOTP from your authenticator app:", handle_totp)
                    return None
                elif 'emailOtp' in auth_data['requiresTwoFactorAuth']:
                    def handle_email_otp(otp):
                        verify_2fa_url = "https://api.vrchat.cloud/api/1/auth/twofactorauth/emailotp/verify"
                        otp_data = {"code": otp, "method": "emailOtp"}
                        otp_response = requests.post(verify_2fa_url, json=otp_data, cookies=cookies, headers=headers)
                        logging.debug(f"Email OTP verification response: {otp_response.status_code}")
                        if otp_response.status_code == 200:
                            combined_cookies = requests.cookies.RequestsCookieJar()
                            combined_cookies.update(response.cookies)
                            combined_cookies.update(otp_response.cookies)
                            save_cookies(combined_cookies)
                            logging.debug(f"Successfully authenticated with email OTP: {combined_cookies.get_dict()}")
                            root.after(0, start_username_update_thread)
                        else:
                            root.after(0, lambda: messagebox.showerror("2FA Failed", "Failed to verify email OTP"))
                    prompt_otp("2FA Required", "Enter the email OTP:", handle_email_otp)
                    return None
                else:
                    root.after(0, lambda: messagebox.showerror("2FA Method Not Supported", "The required 2FA method is not supported."))
                    return None
            else:
                save_cookies(cookies)
                logging.debug(f"Successfully authenticated (No 2FA required): {cookies.get_dict()}")
                root.after(0, start_username_update_thread)
                return cookies
        else:
            root.after(0, lambda: messagebox.showerror("Login Failed", "Failed to authenticate with VRChat API"))
            return None
    except requests.exceptions.RequestException as e:
        root.after(0, lambda: messagebox.showerror("Error", f"Error authenticating with VRChat API: {str(e)}"))
        return None

def save_cookies(cookies):
    with open(cookies_path, 'w') as f:
        cookies_dict = {cookie.name: cookie.value for cookie in cookies}
        json.dump(cookies_dict, f)

def load_cookies():
    try:
        with open(cookies_path, 'r') as f:
            cookies_dict = json.load(f)
            cookies = requests.cookies.RequestsCookieJar()
            for name, value in cookies_dict.items():
                cookies.set(name, value)
            return cookies
    except FileNotFoundError:
        return None
#endregion

#region 📝 Usernames, Log File Functions, and Results Display
# These functions manage user data and update the log display 📃

def extract_user_id(url_or_id):
    # Extracts a VRChat user ID from a URL or string using regex 🔍
    match = re.search(r'usr_[a-f0-9-]+', url_or_id)
    return match.group(0) if match else url_or_id

def update_usernames():
    # Updates usernames by querying the VRChat API and comparing stored names 🔄
    cookies = load_cookies()
    if cookies is None:
        cookies = authenticate_vrchat()
    if cookies is None:
        return
    if os.path.exists(users_file):
        with open(users_file, 'r', encoding='utf-8') as f:
            users_data = json.load(f)
    else:
        users_data = {}
    changes_detected = False
    updated_users = {}
    for username, user_id in list(users_data.items()):
        logging.debug(f"Checking {username} ({user_id})...")
        current_display_name = get_displayname(cookies, user_id)
        if not current_display_name:
            logging.debug(f"Failed to fetch display name for {username} ({user_id}) - Skipping.")
            updated_users[username] = user_id
            continue
        if current_display_name != username:
            logging.debug(f"Name change detected: {username} -> {current_display_name} for {user_id}")
            updated_users[current_display_name] = user_id
            changes_detected = True
        else:
            logging.debug(f"No changes detected for {username} ({user_id}).")
            updated_users[username] = user_id
    if changes_detected:
        with open(users_file, 'w', encoding='utf-8') as f:
            json.dump(updated_users, f, indent=4)
        root.after(0, lambda: messagebox.showinfo("Usernames Updated", "Usernames successfully updated in users.json"))
        update_user_list_display()

def get_displayname(cookies, user_id):
    # Fetches a user's display name from the VRChat API 🕵️‍♂️
    url = f"https://api.vrchat.cloud/api/1/users/{user_id}"
    headers = {'User-Agent': 'FCHWatchlister/1.0 (ftacmoderation@gmail.com)'}
    try:
        response = requests.get(url, cookies=cookies, headers=headers)
        if response.status_code == 200:
            try:
                data = response.json()
                display_name = data.get("displayName") or data.get("username")
                if display_name:
                    return display_name
                else:
                    logging.warning(f"API response missing 'displayName' for {user_id}. Full response: {data}")
                    return None
            except requests.exceptions.JSONDecodeError:
                logging.error(f"Failed to parse JSON for {user_id}. Response content: {response.text}")
                return None
        elif response.status_code == 404:
            logging.error(f"User {user_id} not found (404). Check if the ID is correct.")
        elif response.status_code == 403:
            logging.error(f"Forbidden access for {user_id}. You might need to re-authenticate.")
        else:
            logging.error(f"Error fetching display name for {user_id}. Response: {response.status_code}, Body: {response.text}")
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Error contacting VRChat API for {user_id}: {str(e)}")
        return None

def start_username_update_thread():
    # Starts the process for updating usernames every 12 hours ⏰
    update_usernames()
    def loop():
        update_usernames()
        root.after(43200000, loop)  # 43,200,000 ms = 12 hours
    root.after(43200000, loop)

def get_sorted_log_files(directory):
    # Retrieves and sorts log files by timestamp in the filename 📂
    try:
        files = [f for f in os.listdir(directory) if f.endswith('.txt')]
        sorted_files = sorted(files, key=lambda x: re.search(r'\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}', x).group())
        return sorted_files
    except Exception as e:
        logging.error(f"Error getting sorted log files: {e}")
        return []

def compare_files(log_file):
    """
    Reads a log file and extracts entries matching "OnPlayerJoined".
    Returns a list of tuples: (time_diff_seconds, formatted_string, raw_line). 📄
    """
    entries = []
    try:
        users = load_users_data()  # Load user data from file 📂
        with open(log_file, 'r', encoding='utf-8') as lfile:
            log_entries = [line for line in lfile if "OnPlayerJoined" in line]
        for line in log_entries:
            for username in users:
                if username in line:
                    timestamp_str = line[:19].strip()  # Expecting format: YYYY.MM.DD HH:MM:SS
                    try:
                        log_datetime = datetime.strptime(timestamp_str, "%Y.%m.%d %H:%M:%S")
                        current_time = datetime.now()
                        time_diff = current_time - log_datetime
                        time_diff_seconds = time_diff.total_seconds()
                        date, time_str = timestamp_str.split(' ')
                        time_obj = datetime.strptime(time_str, "%H:%M:%S")
                        time_12_hour = time_obj.strftime("%I:%M:%S %p")
                    except Exception:
                        date, time_12_hour, time_diff_seconds = "Unknown", "Unknown", float('inf')
                    if time_diff_seconds == float('inf'):
                        relative_time = "Unknown"
                    else:
                        days, remainder = divmod(time_diff_seconds, 86400)
                        hours, remainder = divmod(remainder, 3600)
                        minutes, _ = divmod(remainder, 60)
                        if days > 0:
                            relative_time = f"{int(days)} days, {int(hours)} hours ago"
                        elif hours > 0:
                            relative_time = f"{int(hours)} hours, {int(minutes)} minutes ago"
                        else:
                            relative_time = f"{int(minutes)} minutes ago"
                    formatted_entry = f'{username} - Date: {date}, Time: {time_12_hour}, {relative_time}'
                    entries.append((time_diff_seconds, formatted_entry, line.rstrip()))
                    break
    except Exception as e:
        logging.error(f"Error comparing file {log_file}: {e}")
    return entries

def update_ui(entries):
    """
    Updates the log UI with entries.
    Deduplicates and sorts them, then displays them in the text widget. 🖥️
    """
    try:
        unique_entries = {}
        for t, entry, raw_line in entries:
            if entry not in unique_entries or t < unique_entries[entry][0]:
                unique_entries[entry] = (t, raw_line)
        deduped_entries = [(t, entry, raw_line) for entry, (t, raw_line) in unique_entries.items()]
        sorted_entries = sorted(deduped_entries, key=lambda x: x[0])
        result_text.config(state="normal")
        result_text.delete('1.0', tk.END)
        for t, entry, raw_line in sorted_entries:
            logging.debug(f"Printing UI entry (raw): {raw_line}")
            result_text.insert(tk.END, entry + "\n")
        result_text.config(state="disabled")
    except Exception as e:
        logging.error(f"Error updating UI: {e}")

def refresh_log_entries():
    """
    Refreshes the UI by reading the latest log file and updating the text widget.
    """
    try:
        sorted_files = get_sorted_log_files(directory)
        if not sorted_files:
            return
        latest_log_file = os.path.join(directory, sorted_files[-1])
        entries = compare_files(latest_log_file)
        update_ui(entries)
    except Exception as e:
        logging.error(f"Error refreshing log entries: {e}")

def monitor_latest_log_file(directory):
    """
    Efficiently monitors the latest log file for new entries using file seek.
    """
    global stop_event  # Ensure we refer to the global stop_event
    try:
        sorted_files = get_sorted_log_files(directory)
        if not sorted_files:
            logging.warning("No log files found. Waiting...")
            return
        
        latest_log_file = os.path.join(directory, sorted_files[-1])
        last_position = 0  # Keep track of where we last read in the file
        
        with open(latest_log_file, 'r', encoding='utf-8') as lfile:
            lfile.seek(0, os.SEEK_END)
            last_position = lfile.tell()
            
            while not stop_event.is_set():
                lfile.seek(last_position)
                new_lines = lfile.readlines()
                
                if new_lines:
                    last_position = lfile.tell()
                    process_new_log_entries(new_lines)
                time.sleep(2)
    except Exception as e:
        logging.error(f"Error monitoring latest log file: {e}")

def process_new_log_entries(new_lines):
    """
    Processes new log entries and updates the UI accordingly.
    Also plays a sound if a new entry is detected (and not muted). 🔔
    """
    new_entries = []
    users = load_users_data()
    play_sound = False
    
    for line in new_lines:
        if "OnPlayerJoined" in line:
            for username, user_id in users.items():
                if username in line or user_id in line:
                    timestamp_match = re.search(r'\d{4}\.\d{2}\.\d{2} \d{2}:\d{2}:\d{2}', line)
                    
                    if timestamp_match:
                        timestamp = timestamp_match.group()
                        try:
                            log_datetime = datetime.strptime(timestamp, "%Y.%m.%d %H:%M:%S")
                            current_time = datetime.now()
                            time_diff_seconds = (current_time - log_datetime).total_seconds()
                            
                            relative_time = format_relative_time(time_diff_seconds)
                            formatted_entry = f'{username} - Date: {timestamp[:10]}, Time: {timestamp[11:]}, {relative_time}'
                            
                            new_entries.append((time_diff_seconds, formatted_entry, line.rstrip()))
                            play_sound = True
                            logging.info(f'User "{username}" ({user_id}) joined (Timestamp: {timestamp})')
                        except ValueError:
                            continue
                    break
    
    if new_entries:
        root.after(0, lambda: update_ui(new_entries))
        if play_sound and os.path.exists(sound) and not is_muted:
            playsound(sound)

def format_relative_time(seconds):
    """Formats a relative time string from seconds."""
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)
    
    if days > 0:
        return f"{int(days)} days, {int(hours)} hours ago"
    elif hours > 0:
        return f"{int(hours)} hours, {int(minutes)} minutes ago"
    else:
        return f"{int(minutes)} minutes ago"

def load_users_data():
    """
    Loads users from users.json without updating the UI. 📂
    """
    if not os.path.exists(users_file):
        with open(users_file, 'w', encoding='utf-8') as file:
            json.dump({}, file, indent=4)
    try:
        with open(users_file, 'r', encoding='utf-8') as file:
            users_data = json.load(file)
            if not isinstance(users_data, dict):
                users_data = {}
                with open(users_file, 'w', encoding='utf-8') as reset_file:
                    json.dump(users_data, reset_file, indent=4)
    except json.JSONDecodeError:
        users_data = {}
        with open(users_file, 'w', encoding='utf-8') as file:
            json.dump(users_data, file, indent=4)
    return users_data
#endregion

#region 📜 History Button Functionality
def show_history():
    """
    Extracts ALL usernames and user IDs from log lines containing "OnPlayerJoined".
    Displays them in a formatted UI similar to the user list area, with relative join times.
    """
    sorted_files = get_sorted_log_files(directory)
    if not sorted_files:
        messagebox.showinfo("History", "No log files found.")
        return

    latest_log_file = os.path.join(directory, sorted_files[-1])
    user_data = []  # List to store usernames, profile URLs, and join times in order

    print("\n🔍 DEBUG: Scanning log file for 'OnPlayerJoined' entries...")  # Debugging

    with open(latest_log_file, 'r', encoding='utf-8') as file:
        for line in file:
            if "OnPlayerJoined" in line:
                print(f"📜 Found: {line.strip()}")  # Debugging

                timestamp_match = re.search(r'(\d{4}\.\d{2}\.\d{2} \d{2}:\d{2}:\d{2})', line)
                username_match = re.search(r'OnPlayerJoined\s+(.+?)\s+\(', line)
                user_id_match = re.search(r'\((usr_[a-f0-9-]+)\)', line)

                if timestamp_match and username_match and user_id_match:
                    timestamp_str = timestamp_match.group(1)
                    log_datetime = datetime.strptime(timestamp_str, "%Y.%m.%d %H:%M:%S")
                    time_diff_seconds = (datetime.now() - log_datetime).total_seconds()
                    
                    if time_diff_seconds < 60:
                        relative_time = f"{int(time_diff_seconds)} seconds ago"
                    elif time_diff_seconds < 3600:
                        relative_time = f"{int(time_diff_seconds // 60)} minutes ago"
                    elif time_diff_seconds < 86400:
                        relative_time = f"{int(time_diff_seconds // 3600)} hours ago"
                    else:
                        relative_time = f"{int(time_diff_seconds // 86400)} days ago"

                    username = username_match.group(1).strip()
                    user_id = user_id_match.group(1).strip()
                    profile_url = f"https://vrchat.com/home/user/{user_id}"
                    user_data.append((username, user_id, profile_url, relative_time))

                    print(f"✅ Extracted: {username} -> {profile_url} ({relative_time})")  # Debugging

    if not user_data:
        print("⚠️ DEBUG: No usernames were extracted!")  # Debugging
        messagebox.showinfo("History", "No usernames found in the latest log file.")
        return

    print(f"✅ DEBUG: Extracted user data: {user_data}")  # Debugging

    history_window = tk.Toplevel(root)
    history_window.title("Player Join History")
    history_window.geometry("740x400")
    history_window.configure(bg="#333333")  # Match user list background

    frame = tk.Frame(history_window, bg="#555555", highlightthickness=1, highlightbackground="#800000")
    frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    canvas = tk.Canvas(frame, bg="#555555")
    scrollbar = tk.Scrollbar(frame, orient="vertical", command=canvas.yview, bg="#777777")
    inner_frame = tk.Frame(canvas, bg="#555555")

    inner_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0, 0), window=inner_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def add_user_from_history(username, user_id):
        users = load_users_data()
        if username in users:
            messagebox.showinfo("Already Added", f"{username} is already in the user list.")
            return
        users[username] = user_id
        save_users_data(users)
        root.after(0, update_user_list_display)
        root.after(0, refresh_log_entries)
        #messagebox.showinfo("User Added", f"{username} has been added!")




    for row_index, (username, user_id, profile_url, relative_time) in enumerate(reversed(user_data), start=1):  # Maintain original order
        add_button = tk.Button(inner_frame, text="Add", command=lambda u=username, i=user_id: add_user_from_history(u, i),
                               bg="#777777", fg="black", padx=5, pady=5)
        add_button.grid(row=row_index, column=0, padx=5, pady=5, sticky="ew")

        tk.Label(inner_frame, text=username, bg="#777777", fg="black", padx=5, pady=5, anchor="w")\
            .grid(row=row_index, column=1, padx=5, pady=5, sticky="ew")
        tk.Label(inner_frame, text=profile_url, bg="#777777", fg="black", padx=5, pady=5, anchor="w")\
            .grid(row=row_index, column=2, padx=5, pady=5, sticky="ew")
        tk.Label(inner_frame, text=relative_time, bg="#777777", fg="black", padx=5, pady=5, anchor="w")\
            .grid(row=row_index, column=3, padx=5, pady=5, sticky="ew")

    root.after(0, refresh_log_entries)

#endregion

#region 🎨 User List Display (Two-Column Layout)
# This section is heavily commented to explain the UI formatting for the user list! 😎
def update_user_list_display():
    # Clear current items in the scrollable user list frame 🧹
    for widget in user_list_inner_frame.winfo_children():
        widget.destroy()
    users = load_users_data()
    # Create a header row with three columns:
    # - "Delete" column for delete buttons
    # - "Username" column for user names
    # - "Profile URL" column for VRChat profile links
    header = tk.Frame(user_list_inner_frame, bg="#555555")
    header.grid(row=0, column=0, columnspan=3, sticky="ew", padx=2, pady=2)
    tk.Label(header, text="Delete", bg="#777777", fg="black", anchor="center")\
        .grid(row=0, column=0, sticky="ew", padx=2, pady=2)  # Centered header for Delete column 😎
    tk.Label(header, text="Username", bg="#777777", fg="black", anchor="center")\
        .grid(row=0, column=1, sticky="ew", padx=2, pady=2)  # Centered header for Username column ✨
    tk.Label(header, text="Profile URL", bg="#777777", fg="black", anchor="center")\
        .grid(row=0, column=2, sticky="ew", padx=2, pady=2)  # Centered header for Profile URL column 🌐
    
    # Configure columns so that:
    # - Columns 0 and 1 share the same width (uniform "colGroup")
    # - Column 2 is given more space (uniform "colGroup2")
    user_list_inner_frame.grid_columnconfigure(0, weight=1, uniform="colGroup")
    user_list_inner_frame.grid_columnconfigure(1, weight=1, uniform="colGroup")
    user_list_inner_frame.grid_columnconfigure(2, weight=2, uniform="colGroup2")
    
    # For each user, add a row with a Delete button, username, and profile URL 👥
    row_index = 1
    for username, user_id in sorted(users.items()):
        tk.Button(user_list_inner_frame, text="Delete", command=lambda u=username: delete_user(u),
                  bg="#777777", fg="black", padx=5, pady=5)\
            .grid(row=row_index, column=0, sticky="ew", padx=2, pady=2)
        tk.Label(user_list_inner_frame, text=username, bg="#777777", fg="black", padx=5, pady=5, anchor="w")\
            .grid(row=row_index, column=1, sticky="ew", padx=2, pady=2)
        tk.Label(user_list_inner_frame, text=f"https://vrchat.com/home/user/{user_id}", bg="#777777", fg="black", padx=5, pady=5, anchor="w")\
            .grid(row=row_index, column=2, sticky="ew", padx=2, pady=2)
        row_index += 1

def save_users_data(users_dict):
    # Save the user list to users.json 💾
    with open(users_file, 'w', encoding='utf-8') as file:
        json.dump(users_dict, file, indent=4)

def delete_user(username):
    # Remove a user from the list, update the display, and refresh log entries 🗑️
    users = load_users_data()
    if username in users:
        del users[username]
        save_users_data(users)
        update_user_list_display()
        refresh_log_entries()

def add_user():
    # Add a new user from the input fields ➕
    username = username_entry.get().strip()
    url = url_entry.get().strip()
    if username and url:
        users = load_users_data()
        user_id = extract_user_id(url)
        users[username] = user_id
        save_users_data(users)
        update_user_list_display()
        username_entry.delete(0, tk.END)
        url_entry.delete(0, tk.END)
        refresh_log_entries()
#endregion

#region 🚀 Main GUI and Application Initialization
def main():
    try:
        refresh_log_entries()  # Load latest log entries into the UI
        update_user_list_display()  # Update the user list display
        global monitor_thread
        monitor_thread = threading.Thread(target=monitor_latest_log_file, args=(directory,), daemon=True)
        monitor_thread.start()
    except Exception as e:
        logging.error(f"Error in main function: {e}")

def on_closing():
    # Called when the application window is closed ❌
    stop_event.set()
    logging.info("Stopping threads and closing application.")
    time.sleep(1)
    root.destroy()
#endregion

#region 🎨 UI Layout and Styling
# This section defines the overall layout and visual styling of the application 🎨
# Adjust these settings to change the appearance of the UI.
root = tk.Tk()
root.title("VRChat Log Viewer")
root.geometry('800x800')
root.configure(bg="#333333")  # Dark grey background for the main window

# Outer frame: Provides a 20px margin and a dark maroon outline around the main UI 🖼️
main_frame = tk.Frame(root, bg="#333333", padx=20, pady=20, highlightthickness=1, highlightbackground="#800000")
main_frame.pack(fill=tk.BOTH, expand=True)

# The main_frame is divided into two rows using grid:
# - Row 0: Log result UI (top half)
# - Row 1: User list and add-user section (bottom half)
main_frame.rowconfigure(0, weight=1)
main_frame.rowconfigure(1, weight=1)
main_frame.columnconfigure(0, weight=1)

# Top area: Log result UI 📝
top_frame = tk.Frame(main_frame, bg="#555555", highlightthickness=1, highlightbackground="#800000")
top_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
top_frame.rowconfigure(0, weight=1)
top_frame.columnconfigure(0, weight=1)

# result_text: A scrollable text widget for displaying log entries 📃
result_text = scrolledtext.ScrolledText(top_frame, wrap=tk.NONE, state="disabled",
                                          bg="#555555", fg="white",
                                          highlightthickness=1, highlightbackground="#800000")
result_text.grid(row=0, column=0, sticky="nsew")
h_scroll = tk.Scrollbar(top_frame, orient=tk.HORIZONTAL, command=result_text.xview,
                        bg="#555555", highlightthickness=1, highlightbackground="#800000")
result_text.configure(xscrollcommand=h_scroll.set)
h_scroll.grid(row=1, column=0, sticky="ew")

# Bottom area: Contains both the user list and the add-user input section 👥
bottom_frame = tk.Frame(main_frame, bg="#555555", highlightthickness=1, highlightbackground="#800000")
bottom_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
bottom_frame.rowconfigure(1, weight=1)
bottom_frame.columnconfigure(0, weight=1)

user_list_frame = tk.Frame(bottom_frame, bg="#555555", highlightthickness=1, highlightbackground="#800000")
user_list_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

canvas = tk.Canvas(user_list_frame, bg="#555555")
scrollbar = tk.Scrollbar(user_list_frame, orient="vertical", command=canvas.yview)
user_list_inner_frame = tk.Frame(canvas, bg="#555555")  # This is the missing variable

user_list_inner_frame.bind(
    "<Configure>",
    lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
)

canvas.create_window((0, 0), window=user_list_inner_frame, anchor="nw")
canvas.configure(yscrollcommand=scrollbar.set)

canvas.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")


# Add User Input Section (centered) ✍️
input_wrapper = tk.Frame(bottom_frame, bg="#555555")
input_wrapper.grid(row=0, column=0, sticky="ew")
input_wrapper.columnconfigure(0, weight=1)

input_frame = tk.Frame(input_wrapper, bg="#777777", highlightthickness=1, highlightbackground="#800000")
input_frame.grid(row=0, column=0, padx=5, pady=5)
for i in range(5):  # Updated to 5 columns to accommodate the new button
    input_frame.columnconfigure(i, weight=1)

# Create labels and entry fields with detailed comments for editing 😊
username_label = tk.Label(input_frame, text="Username:", bg="#777777", fg="black")  # Label for username
username_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
username_entry = tk.Entry(input_frame, bg="#777777", fg="black", highlightthickness=1, highlightbackground="#800000")  # Entry for username
username_entry.grid(row=0, column=1, padx=5, pady=5, sticky="we")

url_label = tk.Label(input_frame, text="Profile URL:", bg="#777777", fg="black")  # Label for profile URL
url_label.grid(row=0, column=2, padx=5, pady=5, sticky="e")
url_entry = tk.Entry(input_frame, bg="#777777", fg="black", highlightthickness=1, highlightbackground="#800000")  # Entry for profile URL
url_entry.grid(row=0, column=3, padx=5, pady=5, sticky="we")

# "Add User" button (already present)
add_button = tk.Button(input_frame, text="Add User", command=add_user, bg="#777777", fg="black",
                       highlightthickness=1, highlightbackground="#800000")
add_button.grid(row=0, column=4, padx=5, pady=5)

# New "History" button placed next to "Add User" (column 5)
history_button = tk.Button(input_frame, text="History", command=show_history, bg="#777777", fg="black",
                           highlightthickness=1, highlightbackground="#800000")

history_button.grid(row=0, column=5, padx=5, pady=5)
#endregion

#region 🚀 Initial Processes and Closing Protocol
# Start initial processes: update user list and log entries 🔄, and bind closing protocol 🚪
update_user_list_display()
start_username_update_thread()
root.protocol("WM_DELETE_WINDOW", on_closing)
main()
root.mainloop()
#endregion
