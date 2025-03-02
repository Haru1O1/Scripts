from pynput import keyboard
import ctypes
import subprocess
import pyautogui
import platform
import time
import os

# Store the key presses in a Dictionary
key_dict = {}
# Store the past key pressed
past_key = None
count = 0

def disable_user_input():
    # Block user input
    ctypes.windll.user32.BlockInput(True)
    time.sleep(5)
    # Unblock user input
    ctypes.windll.user32.BlockInput(False)

# Minimizes all windows on Windows
def minimize_all_windows_win():
    pyautogui.hotkey('win', 'd') # Windows key + D key

def on_press(key):
    global past_key
    global count

    # increment key count
    count += 1
    # if the number of keys hits 25 all user input will be blocked aka no mouse no keyboard
    # it will then reset
    if count == 25: 
        if platform.system() == "Windows":
            disable_user_input()
        count = 0
    try:
        if hasattr(key, 'char'):
            key_name = key.char
        else:
            key_name = str(key)
        if key_name in key_dict: 
            key_dict[key_name] += 1
        else:
            key_dict[key_name] = 1
            # Remove the past key pressed
            key_dict.pop(past_key, None)
        past_key = key_name
        #print(f"Key {key_name} is pressed.")
        if key_dict[key_name] == 2:
            if platform.system() == "Windows":
                minimize_all_windows_win()
    except AttributeError:
        key_name = str(key)
        if key_name in key_dict:
            key_dict[key_name] += 1
        else:
            key_dict[key_name] = 1
            # Remove the past key pressed
            key_dict.pop(past_key, None)
        past_key = key_name
        #print(f"Special key {key_name} is pressed")
        if key_dict[key_name] == 2:
            if platform.system() == "Windows":
                minimize_all_windows_win()

with keyboard.Listener(on_press = on_press) as listener:
    listener.join()
