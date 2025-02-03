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

# Ensure Tkinter root is initialized once
root = tk.Tk()
root.withdraw()  # Hide the root window

stop_event = threading.Event()  # Global flag for stopping the thread

# Determine file paths
directory = os.path.join(os.getenv('APPDATA').replace('Roaming', 'LocalLow'), 'VRChat', 'VRChat')
settings_path = os.path.join(os.path.dirname(__file__), "settings.json")
users_file = os.path.join(os.path.dirname(__file__), "users.json")
sound = os.path.join(os.path.dirname(__file__), "sound.mp3")
cookies_path = os.path.join(os.path.dirname(__file__), "session_cookies.json")
login_path = os.path.join(os.path.dirname(__file__), "login.json")

# Function to load settings.json
def load_settings():
    if os.path.exists(settings_path):
        with open(settings_path, 'r') as file:
            settings = json.load(file)  # Load settings.json
    else:
        return {}  # Return empty dictionary if file does not exist

    # Check and remove login credentials if they exist
    keys_to_remove = ["vrchat_username", "vrchat_password"]
    modified = False

    for key in keys_to_remove:
        if key in settings:
            del settings[key]  # Remove sensitive keys
            modified = True

    # Save the updated settings.json if changes were made
    if modified:
        with open(settings_path, 'w') as file:
            json.dump(settings, file, indent=4)

    return settings  # Return the cleaned settings dictionary


settings = load_settings()  # Load settings from settings.json
is_muted = settings.get("is_muted", False)  # Default to False if not found

# Function to save settings.json (excluding credentials)
def save_settings(data):
    if "vrchat_username" in data:
        del data["vrchat_username"]
    if "vrchat_password" in data:
        del data["vrchat_password"]
    
    with open(settings_path, "w") as file:
        json.dump(data, file, indent=4)

# Function to load login credentials from login.json
def load_login():
    if os.path.exists(login_path):
        with open(login_path, 'r') as file:
            return json.load(file)
    return {}  # Return empty dictionary if login.json doesn't exist

# Function to save login credentials to login.json
def save_login(username, password):
    credentials = {
        "vrchat_username": username,
        "vrchat_password": password
    }
    with open(login_path, "w") as file:
        json.dump(credentials, file, indent=4)

# Function to read mute state from JSON
# Function to read mute state from settings.json
def read_mute_state():
    settings = load_settings()  # Use the function that safely loads settings
    return settings.get("is_muted", False)  # Default to False if missing


# Function to write mute state to JSON
def write_mute_state(state):
    settings = load_settings()  # Load settings safely
    settings["is_muted"] = state  # Update mute state

    with open(settings_path, "w") as file:
        json.dump(settings, file, indent=4)  # Save updated settings

    print(f"Updated is_muted to {state} in settings.json")


# Function to toggle mute state
def toggle_mute():
    global is_muted
    is_muted = not is_muted
    mute_button.config(text="Unmute" if is_muted else "Mute")
    write_mute_state(is_muted)  # This should now be updated to use load_settings()


# Authenticate VRChat
# Function to extract user ID from a full VRChat URL or raw ID
def extract_user_id(url_or_id):
    match = re.search(r'usr_[a-f0-9-]+', url_or_id)
    return match.group(0) if match else url_or_id  # Return extracted ID or input if no match

# Function to authenticate with VRChat and handle 2FA if needed
# Create a queue to store OTP input from the main thread
otp_queue = queue.Queue()

def prompt_otp(title, message, callback):
    """Runs the OTP input dialog in the main Tkinter thread without freezing the UI, then continues authentication."""
    
    def ask_otp():
        otp = simpledialog.askstring(title, message, parent=root)
        if otp:
            root.after(0, lambda: callback(otp))  # Continue authentication in the main thread

    root.after(0, ask_otp)  # Schedule OTP prompt in the main thread




def authenticate_vrchat():
    # Load credentials from login.json
    credentials = load_login()

    vrchat_username = credentials.get('vrchat_username', None)
    vrchat_password = credentials.get('vrchat_password', None)

    def ask_for_login():
        nonlocal vrchat_username, vrchat_password  # Allows modification of outer variables
        vrchat_username = simpledialog.askstring("Login Required", "Enter your VRChat username/email:")
        vrchat_password = simpledialog.askstring("Login Required", "Enter your VRChat password:", show='*')

        if vrchat_username and vrchat_password:
            save_login(vrchat_username, vrchat_password)  # Save new credentials

        # Continue authentication after getting login details
        root.after(0, lambda: authenticate_vrchat_continue(vrchat_username, vrchat_password))

    if not vrchat_username or not vrchat_password:
        root.after(0, ask_for_login)  # Ensure GUI functions run in the main thread
        return None  # Exit function and wait for credentials

    return authenticate_vrchat_continue(vrchat_username, vrchat_password)


def authenticate_vrchat_continue(vrchat_username, vrchat_password):
    login_url = "https://api.vrchat.cloud/api/1/auth/user"
    headers = {'User-Agent': 'FCHWatchlister/1.0 (ftacmoderation@gmail.com)'}

    try:
        response = requests.get(login_url, auth=(vrchat_username, vrchat_password), headers=headers)
        print(f"Initial login response: {response.status_code}")

        if response.status_code == 200:
            auth_data = response.json()
            cookies = response.cookies

            # Check if 2FA is required
            if 'requiresTwoFactorAuth' in auth_data:
                if 'totp' in auth_data['requiresTwoFactorAuth']:
                    def handle_totp(totp):
                        verify_2fa_url = "https://api.vrchat.cloud/api/1/auth/twofactorauth/totp/verify"
                        otp_data = {"code": totp, "method": "totp"}

                        otp_response = requests.post(verify_2fa_url, json=otp_data, cookies=cookies, headers=headers)
                        print(f"TOTP verification response: {otp_response.status_code}")

                        if otp_response.status_code == 200:
                            combined_cookies = requests.cookies.RequestsCookieJar()
                            combined_cookies.update(response.cookies)
                            combined_cookies.update(otp_response.cookies)  # Include the 2FA token

                            save_cookies(combined_cookies)  # ✅ Ensure cookies get saved
                            print(f"Successfully authenticated with TOTP: {combined_cookies.get_dict()}")
                            root.after(0, start_username_update_thread)  # ✅ Restart username checks
                        else:
                            root.after(0, lambda: messagebox.showerror("2FA Failed", "Failed to verify TOTP"))

                    prompt_otp("2FA Required", "Enter the TOTP from your authenticator app:", handle_totp)
                    return None  # Stop execution and wait for OTP callback

                elif 'emailOtp' in auth_data['requiresTwoFactorAuth']:
                    def handle_email_otp(otp):
                        verify_2fa_url = "https://api.vrchat.cloud/api/1/auth/twofactorauth/emailotp/verify"
                        otp_data = {"code": otp, "method": "emailOtp"}

                        otp_response = requests.post(verify_2fa_url, json=otp_data, cookies=cookies, headers=headers)
                        print(f"OTP verification response: {otp_response.status_code}")

                        if otp_response.status_code == 200:
                            combined_cookies = requests.cookies.RequestsCookieJar()
                            combined_cookies.update(response.cookies)
                            combined_cookies.update(otp_response.cookies)  # Include the 2FA token

                            save_cookies(combined_cookies)  # ✅ Ensure cookies get saved
                            print(f"Successfully authenticated with email OTP: {combined_cookies.get_dict()}")
                            root.after(0, start_username_update_thread)  # ✅ Restart username checks
                        else:
                            root.after(0, lambda: messagebox.showerror("2FA Failed", "Failed to verify email OTP"))

                    prompt_otp("2FA Required", "Enter the email OTP:", handle_email_otp)
                    return None  # Stop execution and wait for OTP callback

                else:
                    root.after(0, lambda: messagebox.showerror("2FA Method Not Supported", "The required 2FA method is not supported."))
                    return None
            else:
                # ✅ Save cookies if 2FA is not required
                save_cookies(response.cookies)
                print(f"Successfully authenticated (No 2FA required): {response.cookies.get_dict()}")
                root.after(0, start_username_update_thread)  # ✅ Restart username checks
                return response.cookies
        else:
            root.after(0, lambda: messagebox.showerror("Login Failed", "Failed to authenticate with VRChat API"))
            return None

    except requests.exceptions.RequestException as e:
        root.after(0, lambda: messagebox.showerror("Error", f"Error authenticating with VRChat API: {str(e)}"))
        return None


# Function to save cookies
def save_cookies(cookies):
    with open(cookies_path, 'w') as f:  # Use the corrected path
        cookies_dict = {cookie.name: cookie.value for cookie in cookies}
        json.dump(cookies_dict, f)

# Function to load cookies
def load_cookies():
    try:
        with open(cookies_path, 'r') as f:  # Use the corrected path
            cookies_dict = json.load(f)
            cookies = requests.cookies.RequestsCookieJar()
            for name, value in cookies_dict.items():
                cookies.set(name, value)
            return cookies
    except FileNotFoundError:
        return None

# Function to update usernames in users.json
def update_usernames():
    cookies = load_cookies()
    if cookies is None:
        cookies = authenticate_vrchat()
    if cookies is None:
        return  # Exit if authentication fails

    # Load existing usernames from users.json
    if os.path.exists(users_file):
        with open(users_file, 'r', encoding='utf-8') as f:
            users_data = json.load(f)
    else:
        users_data = {}

    changes_detected = False
    updated_users = {}  # Temporary storage for updated usernames

    # ✅ Iterate over a copy of items() to prevent modification errors
    for username, user_id in list(users_data.items()):
        print(f"\nChecking {username} ({user_id})...")  # Show username + ID

        # Fetch current display name from VRChat API
        current_display_name = get_displayname(cookies, user_id)
        if not current_display_name:
            print(f"❌ Failed to fetch display name for {username} ({user_id}) - Skipping.")
            updated_users[username] = user_id  # Preserve unchanged users
            continue  # Skip this user if we can't fetch their name

        if current_display_name != username:
            print(f"✅ Name change detected: {username} -> {current_display_name} for {user_id}")
            updated_users[current_display_name] = user_id  # Keep ID, update username
            changes_detected = True
        else:
            print(f"No changes detected for {username} ({user_id})...")
            updated_users[username] = user_id  # Keep original user if unchanged

    # Save updated names to users.json
    if changes_detected:
        with open(users_file, 'w', encoding='utf-8') as f:
            json.dump(updated_users, f, indent=4)

        root.after(0, lambda: messagebox.showinfo("Usernames Updated", "Usernames successfully updated in users.json"))

        # ✅ Refresh the user list UI
        root.after(0, load_users)  # Ensure UI updates correctly
    else:
        root.after(0, lambda: messagebox.showinfo("No Changes", "No changes detected in usernames."))


# Function to get the display name from VRChat API
def get_displayname(cookies, user_id):
    url = f"https://api.vrchat.cloud/api/1/users/{user_id}"
    headers = {'User-Agent': 'FCHWatchlister/1.0 (ftacmoderation@gmail.com)'}

    try:
        response = requests.get(url, cookies=cookies, headers=headers)

        if response.status_code == 200:
            try:
                data = response.json()  # Safely parse JSON
                display_name = data.get("displayName") or data.get("username")  # Ensure we get a valid name
                
                if display_name:
                    return display_name
                else:
                    print(f"⚠️ API response missing 'displayName' for {user_id}. Full response: {data}")
                    return None
            except requests.exceptions.JSONDecodeError:
                print(f"❌ Failed to parse JSON for {user_id}. Response content: {response.text}")
                return None

        elif response.status_code == 404:
            print(f"❌ Error: User {user_id} not found (404). Check if the ID is correct.")
        elif response.status_code == 403:
            print(f"⛔ Error: Forbidden access for {user_id}. You might need to re-authenticate.")
        else:
            print(f"❌ Error fetching display name for {user_id}. Response: {response.status_code}, Body: {response.text}")

        return None

    except requests.exceptions.RequestException as e:
        print(f"❌ Error contacting VRChat API for {user_id}: {str(e)}")
        return None

# Function to update usernames on app start
def start_username_update_thread():
    thread = threading.Thread(target=update_usernames)
    thread.daemon = True
    thread.start()

# Function to get sorted log files
def get_sorted_log_files(directory):
    try:
        files = [f for f in os.listdir(directory) if f.endswith('.txt')]
        sorted_files = sorted(files, key=lambda x: re.search(r'\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}', x).group())
        return sorted_files
    except Exception as e:
        print(f"Error getting sorted log files: {e}")
        return []

# Function to compare files and find matches
def compare_files(log_file):
    matches = []
    try:
        if os.path.exists(users_file):
            with open(users_file, 'r', encoding='utf-8') as ufile:
                keywords = json.load(ufile).keys()  # Get usernames from JSON
        else:
            keywords = []

        with open(log_file, 'r', encoding='utf-8') as lfile:
            log_entries = [line for line in lfile if "OnPlayerJoined" in line]

        for line in log_entries:
            for keyword in keywords:
                if keyword in line:
                    matches.append(f"User {keyword} joined!")
                    break
    except Exception as e:
        print(f"Error comparing files: {e}")
    return matches

# Function to update the UI with results
def update_ui(matches):
    if matches:
        for match in matches:
            result_text.insert('1.0', match + "\n")

# Function to read and process old log files
def read_old_log_files():
    try:
        sorted_files = get_sorted_log_files(directory)
        for log_file in sorted_files[:-1]:  
            log_file_path = os.path.join(directory, log_file)
            matches = compare_files(log_file_path)
            update_ui(matches)
    except Exception as e:
        print(f"Error reading old log files: {e}")

# Function to monitor the latest log file for changes
def monitor_latest_log_file():
    try:
        latest_log_file = os.path.join(directory, get_sorted_log_files(directory)[-1])  
        while not stop_event.is_set():  # Check if stop is triggered
            matches = compare_files(latest_log_file)
            if matches:
                update_ui(matches)
                if not is_muted:
                    playsound(sound)
            time.sleep(2)
    except Exception as e:
        print(f"Error monitoring latest log file: {e}")

# Function to load users from JSON
def load_users():
    """Loads users.json and updates the UI. If it doesn't exist, create an empty file."""
    if not os.path.exists(users_file):
        print("⚠️ users.json not found. Creating a new one...")
        with open(users_file, 'w', encoding='utf-8') as file:
            json.dump({}, file, indent=4)  # Create an empty JSON object

    try:
        with open(users_file, 'r', encoding='utf-8') as file:
            data = json.load(file)  # Load the user data
            print("✅ Loaded users from users.json:", data)  # Debugging output
    except json.JSONDecodeError:
        print("❌ Error: Invalid JSON format in users.json. Resetting file.")
        data = {}
        with open(users_file, 'w', encoding='utf-8') as file:
            json.dump(data, file, indent=4)

    # ✅ Clear the users_text widget before inserting new data
    users_text.delete('1.0', tk.END)

    # ✅ Populate the users_text widget with loaded data
    for username, user_id in data.items():
        users_text.insert(tk.END, f"{username}: https://vrchat.com/home/user/{user_id}\n")

    print("✅ Users loaded into UI successfully!")




# Function to save users to JSON
def extract_user_id(url_or_id):
    """Extracts the user ID from a full VRChat profile URL or returns the input if it's already an ID."""
    match = re.search(r'usr_[a-f0-9-]+', url_or_id)
    return match.group(0) if match else url_or_id  # Return extracted ID or input if no match

def save_users():
    try:
        users_content = users_text.get('1.0', tk.END).strip()
        users_dict = {}

        for line in users_content.split("\n"):
            if ": " in line:
                user, url = line.split(": ", 1)
                user_id = extract_user_id(url.strip())  # Extract the user ID from the URL or keep it
                users_dict[user.strip()] = user_id  # Save only the ID

        with open(users_file, 'w', encoding='utf-8') as file:
            json.dump(users_dict, file, indent=4)

        print("✅ users.json updated successfully!")

    except Exception as e:
        print(f"❌ Error saving users: {e}")


# Function to add new users from input fields
def add_user():
    username = username_entry.get().strip()
    url = url_entry.get().strip()

    if username and url:
        users_text.insert(tk.END, f"{username}: {url}\n")
        username_entry.delete(0, tk.END)
        url_entry.delete(0, tk.END)

        save_users()  # ✅ Immediately save to users.json
        load_users()  # ✅ Refresh the UI so the new user appears


# GUI Setup
root = tk.Tk()
root.title("VRChat Log Viewer")
root.geometry('800x800')  # **Smaller window size for better layout**

label = tk.Label(root, text="FCH Watchlister", font=("Helvetica", 14))
label.pack(pady=10)

mute_button = tk.Button(root, text="Unmute" if is_muted else "Mute", command=toggle_mute)
mute_button.pack(padx=10, pady=5, anchor='nw')

# **Reduced result text area height to prevent UI cutoff**
result_text = scrolledtext.ScrolledText(root, wrap=tk.NONE, width=80, height=15)  # **Smaller height**
result_text.pack(pady=10, fill=tk.BOTH, expand=True)

users_frame = tk.Frame(root)
users_frame.pack(pady=5, fill=tk.X)

users_label = tk.Label(users_frame, text="User list (Username: URL)", font=("Helvetica", 12))
users_label.pack()

# **Made this slightly smaller so buttons stay visible**
users_text = scrolledtext.ScrolledText(users_frame, wrap=tk.NONE, width=60, height=7)  # **Smaller height**
users_text.pack(pady=5, padx=10, fill=tk.BOTH)

input_frame = tk.Frame(users_frame)
input_frame.pack(pady=5)

username_label = tk.Label(input_frame, text="Username:")
username_label.pack(side=tk.LEFT, padx=5)
username_entry = tk.Entry(input_frame, width=15)
username_entry.pack(side=tk.LEFT, padx=5)

url_label = tk.Label(input_frame, text="Profile URL:")
url_label.pack(side=tk.LEFT, padx=5)
url_entry = tk.Entry(input_frame, width=30)
url_entry.pack(side=tk.LEFT, padx=5)

buttons_frame = tk.Frame(users_frame)
buttons_frame.pack(pady=5)

add_button = tk.Button(buttons_frame, text="Add User", command=add_user)
add_button.pack(side=tk.LEFT, padx=5)

save_button = tk.Button(buttons_frame, text="Save", command=save_users)
save_button.pack(side=tk.LEFT, padx=5)

update_button = tk.Button(root, text="Update Usernames", command=start_username_update_thread)
update_button.pack(pady=10)

# Load users initially
load_users()

# Run the update process automatically on start
start_username_update_thread()

monitor_thread = threading.Thread(target=monitor_latest_log_file, daemon=True)
monitor_thread.start()

def on_closing():
    stop_event.set()  # Stop monitoring thread
    root.quit()       # Quit Tkinter mainloop
    root.destroy()    # Destroy the GUI window
    os._exit(0)       # Force kill the script (last resort if needed)

root.protocol("WM_DELETE_WINDOW", on_closing)

root.mainloop()
