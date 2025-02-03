import os
import re
import tkinter as tk
from tkinter import scrolledtext
import time
import threading
from datetime import datetime
from playsound import playsound

#python -m PyInstaller --onefile --windowed FCH_Watchlister_Tool.py
# File to store mute state
settings_file = 'settings.txt'

# Function to read mute state from file
def read_mute_state():
    if os.path.exists(settings_file):
        with open(settings_file, 'r') as file:
            state = file.read().strip()
            return state == 'muted'
    return True  # Default to muted if file doesn't exist

# Function to write mute state to file
def write_mute_state(state):
    with open(settings_file, 'w') as file:
        file.write('muted' if state else 'unmuted')

# Global variable to track mute state
is_muted = read_mute_state()

def toggle_mute():
    global is_muted
    is_muted = not is_muted
    mute_button.config(text="Unmute" if is_muted else "Mute")
    write_mute_state(is_muted)

def get_sorted_log_files(directory):
    try:
        files = [f for f in os.listdir(directory) if f.endswith('.txt')]
        sorted_files = sorted(files, key=lambda x: re.search(r'\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}', x).group())
        return sorted_files
    except Exception as e:
        print(f"Error getting sorted log files: {e}")
        return []

def compare_files(log_file, users_file):
    matches = []
    try:
        with open(users_file, 'r', encoding='utf-8') as ufile:
            keywords = [line.strip() for line in ufile if line.strip()]  # Remove extra whitespace and empty lines
        
        print(f"Keywords: {keywords}")  # Debug statement
        
        with open(log_file, 'r', encoding='utf-8') as lfile:
            lines = lfile.readlines()
        
        print(f"Number of lines in log file: {len(lines)}")  # Debug statement
        
        log_entries = [line for line in lines if "OnPlayerJoined" in line]
        
        for line in log_entries:
            print(f"Line: {line}")  # Debug statement
            for keyword in keywords:
                if keyword in line:
                    print(f"Matched keyword: {keyword}")  # Debug statement
                    timestamp = line[:19].strip()
                    date, time_str = timestamp.split(' ')
                    time_obj = datetime.strptime(time_str, "%H:%M:%S")
                    time_12_hour = time_obj.strftime("%I:%M:%S %p")
                    log_datetime = datetime.strptime(timestamp, "%Y.%m.%d %H:%M:%S")
                    current_time = datetime.now()
                    time_diff = current_time - log_datetime
                    days, remainder = divmod(time_diff.total_seconds(), 86400)
                    hours, remainder = divmod(remainder, 3600)
                    minutes, _ = divmod(remainder, 60)
                    if days > 0:
                        relative_time = f"{int(days)} days, {int(hours)} hours ago"
                    elif hours > 0:
                        relative_time = f"{int(hours)} hours, {int(minutes)} minutes ago"
                    else:
                        relative_time = f"{int(minutes)} minutes ago"
                    matches.append(f'{keyword} - Date: {date}, Time: {time_12_hour}, {relative_time}')
                    break
    except Exception as e:
        print(f"Error comparing files: {e}")
    return matches

def update_ui(matches):
    try:
        if matches:
            for match in matches:
                result_text.insert('1.0', match + "\n")
    except Exception as e:
        print(f"Error updating UI: {e}")


def read_old_log_files(directory, users_file):
    try:
        sorted_files = get_sorted_log_files(directory)
        for log_file in sorted_files[:-1]:  # Exclude the latest log file
            log_file_path = os.path.join(directory, log_file)
            matches = compare_files(log_file_path, users_file)
            update_ui(matches)  # Update the UI with old log file entries
    except Exception as e:
        print(f"Error reading old log files: {e}")

def monitor_latest_log_file(directory, users_file):
    try:
        last_checked_size = 0
        latest_log_file = os.path.join(directory, get_sorted_log_files(directory)[-1])  # Get the latest log file
        last_processed_line = ""
        
        while True:
            file_size = os.path.getsize(latest_log_file)
            if file_size > last_checked_size:
                with open(latest_log_file, 'r', encoding='utf-8') as lfile:
                    lfile.seek(last_checked_size)
                    new_lines = lfile.readlines()
                
                matches = []
                play_sound = False
                with open(users_file, 'r', encoding='utf-8') as ufile:
                    keywords = ufile.read().splitlines()
                
                log_entries = [line for line in new_lines if "OnPlayerJoined" in line]
                
                for line in log_entries:
                    if line != last_processed_line:
                        last_processed_line = line
                        for keyword in keywords:
                            if keyword in line:
                                timestamp = line[:19].strip()
                                date, time_str = timestamp.split(' ')
                                time_obj = datetime.strptime(time_str, "%H:%M:%S")
                                time_12_hour = time_obj.strftime("%I:%M:%S %p")
                                log_datetime = datetime.strptime(timestamp, "%Y.%m.%d %H:%M:%S")
                                current_time = datetime.now()
                                time_diff = current_time - log_datetime
                                days, remainder = divmod(time_diff.total_seconds(), 86400)
                                hours, remainder = divmod(remainder, 3600)
                                minutes, _ = divmod(remainder, 60)
                                if days > 0:
                                    relative_time = f"{int(days)} days, {int(hours)} hours ago"
                                elif hours > 0:
                                    relative_time = f"{int(hours)} hours, {int(minutes)} minutes ago"
                                else:
                                    relative_time = f"{int(minutes)} minutes ago"
                                matches.append(f'{keyword} - Date: {date}, Time: {time_12_hour}, {relative_time}')
                                print(f"Match found: {keyword}")  # Debug statement
                                play_sound = True
                                break
                
                if matches:
                    update_ui(matches)
                    if play_sound and not is_muted:
                        playsound('sound.mp3')
                
                last_checked_size = file_size
            
            time.sleep(2)
    except Exception as e:
        print(f"Error monitoring latest log file: {e}")

def main():
    try:
        global directory, users_file
        directory = os.path.join(os.getenv('APPDATA').replace('Roaming', 'LocalLow'), 'VRChat', 'VRChat')
        users_file = 'users.txt'
        
        read_old_log_files(directory, users_file)
        load_users()
        
        monitoring_thread = threading.Thread(target=monitor_latest_log_file, args=(directory, users_file))
        monitoring_thread.daemon = True
        monitoring_thread.start()
    except Exception as e:
        print(f"Error in main function: {e}")

def load_users():
    try:
        with open(users_file, 'r', encoding='utf-8') as file:
            users_text.delete('1.0', tk.END)
            users_text.insert(tk.END, file.read())
    except Exception as e:
        print(f"Error loading users: {e}")

def save_users():
    try:
        with open(users_file, 'w', encoding='utf-8') as file:
            users_content = users_text.get('1.0', tk.END).strip()
            file.write(users_content)
        
        users_text.delete('1.0', tk.END)
        load_users()
        
        # Clear the result_text widget
        result_text.delete('1.0', tk.END)
        
        # Re-read old log files and update the UI
        read_old_log_files(directory, users_file)
        
        # Read the latest log file and update the UI
        latest_log_file = os.path.join(directory, get_sorted_log_files(directory)[-1])
        matches = compare_files(latest_log_file, users_file)
        update_ui(matches)
    except Exception as e:
        print(f"Error saving users: {e}")


# Create the main window
root = tk.Tk()
root.title("VRChat Log Viewer")

# Set the window dimensions
root.geometry('800x800')

# Create a label widget
label = tk.Label(root, text="FCH Watchlister", font=("Helvetica", 14))
label.pack(pady=10)

# Create a mute button at the top left
mute_button = tk.Button(root, text="Unmute" if is_muted else "Mute", command=toggle_mute)
mute_button.pack(padx=10, pady=10, anchor='nw')

# Create a scrolled text widget for results
result_text = scrolledtext.ScrolledText(root, wrap=tk.NONE, width=100, height=30)
result_text.pack(pady=20, fill=tk.BOTH, expand=True)

# Add horizontal scrollbar
h_scroll = tk.Scrollbar(result_text, orient=tk.HORIZONTAL, command=result_text.xview)
result_text.configure(xscrollcommand=h_scroll.set)
h_scroll.pack(side=tk.BOTTOM, fill=tk.X)

# Create a smaller frame for users.txt editor
users_frame = tk.Frame(root)
users_frame.pack(pady=10, fill=tk.X, expand=False)

# Add a centered label for the users.txt editor
users_label = tk.Label(users_frame, text="User list", font=("Helvetica", 12))
users_label.pack()

# Create a scrolled text widget for users.txt
users_text = scrolledtext.ScrolledText(users_frame, wrap=tk.NONE, width=80, height=10)
users_text.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)

# Add buttons for saving users.txt
buttons_frame = tk.Frame(users_frame)
buttons_frame.pack(pady=5)

save_button = tk.Button(buttons_frame, text="Save", command=save_users)
save_button.pack(side=tk.LEFT, padx=5)

# Run the main function automatically on startup
main()

# Run the application
root.mainloop()
