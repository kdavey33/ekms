import curses
import curses.textpad
import os
import datetime
from ekms_crypto import init_master_file, load_keys, ensure_current_year_keys, encrypt_file, decrypt_file, EKMSCryptoError, MASTER_KEYS_FILE
from ekms_utils import secure_delete, get_all_files
import base64

def draw_menu(stdscr, selected_row_idx, options, title, scrub_enabled=False):
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    
    # Draw title
    title_text = f" EKMS v2 - {title} "
    stdscr.attron(curses.color_pair(1))
    stdscr.addstr(0, max(0, w//2 - len(title_text)//2), title_text)
    stdscr.attroff(curses.color_pair(1))
    
    # Draw options
    for idx, row in enumerate(options):
        x = w//2 - len(row)//2
        y = h//2 - len(options)//2 + idx
        if idx == selected_row_idx:
            stdscr.attron(curses.color_pair(2))
            stdscr.addstr(y, x, row)
            stdscr.attroff(curses.color_pair(2))
        else:
            stdscr.addstr(y, x, row)
            
    # Draw status bar
    status = f" Secure Scrub: {'[ON]' if scrub_enabled else '[OFF]'} (Toggle with 'S') | 'Q' to Quit "
    stdscr.attron(curses.color_pair(3))
    stdscr.addstr(h-1, 0, status + " " * max(0, w - len(status) - 1))
    stdscr.attroff(curses.color_pair(3))
    
    stdscr.refresh()

def prompt_input(stdscr, prompt_text, is_password=False):
    curses.curs_set(1)
    h, w = stdscr.getmaxyx()
    stdscr.clear()
    
    stdscr.addstr(h//2 - 2, max(0, w//2 - len(prompt_text)//2), prompt_text)
    
    # Create a window for input
    input_win = curses.newwin(1, w-4, h//2, 2)
    input_win.keypad(True)
    stdscr.refresh()
    
    if is_password:
        curses.noecho()
    else:
        curses.echo()
        
    input_text = ""
    while True:
        ch = input_win.getch()
        if ch in (10, 13): # Enter
            break
        elif ch in (8, 127, curses.KEY_BACKSPACE):
            if len(input_text) > 0:
                input_text = input_text[:-1]
                input_win.clear()
                if is_password:
                    input_win.addstr(0, 0, "*" * len(input_text))
                else:
                    input_win.addstr(0, 0, input_text)
        else:
            if 32 <= ch <= 126:
                input_text += chr(ch)
                if is_password:
                    input_win.addstr(0, 0, "*" * len(input_text))
                else:
                    input_win.addstr(0, 0, input_text)
    
    curses.noecho()
    curses.curs_set(0)
    return input_text

def show_message(stdscr, message):
    h, w = stdscr.getmaxyx()
    stdscr.clear()
    lines = message.split('\\n')
    for i, line in enumerate(lines):
        stdscr.addstr(max(0, h//2 - len(lines)//2 + i), max(0, w//2 - len(line)//2), line)
    stdscr.addstr(h-2, max(0, w//2 - 14), "Press any key to continue...")
    stdscr.refresh()
    stdscr.getch()

def file_browser(stdscr, title):
    current_dir = os.path.expanduser("~")
    selected_paths = set()
    cursor_idx = 0
    top_idx = 0
    
    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        
        try:
            items = os.listdir(current_dir)
        except PermissionError:
            items = []
            
        dirs = []
        files = []
        for item in items:
            try:
                full_path = os.path.join(current_dir, item)
                if os.path.isdir(full_path):
                    dirs.append(item)
                else:
                    files.append(item)
            except Exception:
                pass
                
        dirs.sort()
        files.sort()
        
        display_items = [".."] + dirs + files
        
        # Adjust scrolling
        if cursor_idx < top_idx:
            top_idx = cursor_idx
        elif cursor_idx >= top_idx + h - 4:
            top_idx = cursor_idx - (h - 4) + 1
            
        # Draw Title
        title_str = f" {title} - {current_dir} "
        stdscr.attron(curses.color_pair(1))
        stdscr.addstr(0, 0, title_str[:w].center(w))
        stdscr.attroff(curses.color_pair(1))
        
        # Draw items
        for i in range(h - 4):
            item_idx = top_idx + i
            if item_idx >= len(display_items):
                break
                
            item = display_items[item_idx]
            full_path = os.path.abspath(os.path.join(current_dir, item)) if item != ".." else os.path.abspath(os.path.join(current_dir, ".."))
            
            is_dir = os.path.isdir(full_path)
            is_selected = full_path in selected_paths
            
            prefix = "[x] " if is_selected else "[ ] "
            if item == "..":
                prefix = "    "
                display_str = f"{prefix}.."
            else:
                display_str = f"{prefix}{item}{'/' if is_dir else ''}"
                
            y = i + 2
            x = 2
            
            if item_idx == cursor_idx:
                stdscr.attron(curses.color_pair(2))
                stdscr.addstr(y, x, display_str[:w-4])
                stdscr.attroff(curses.color_pair(2))
            else:
                stdscr.addstr(y, x, display_str[:w-4])
                
        # Status bar
        status = f" Sel: {len(selected_paths)} | Space: Select | Enter: Open | C: Confirm | Q: Cancel "
        stdscr.attron(curses.color_pair(3))
        stdscr.addstr(h-1, 0, status[:w-1].ljust(w-1))
        stdscr.attroff(curses.color_pair(3))
        
        stdscr.refresh()
        key = stdscr.getch()
        
        if key == curses.KEY_UP and cursor_idx > 0:
            cursor_idx -= 1
        elif key == curses.KEY_DOWN and cursor_idx < len(display_items) - 1:
            cursor_idx += 1
        elif key in (10, 13): # Enter
            item = display_items[cursor_idx]
            full_path = os.path.abspath(os.path.join(current_dir, item))
            if os.path.isdir(full_path):
                try:
                    os.listdir(full_path) # Check perm
                    current_dir = full_path
                    cursor_idx = 0
                    top_idx = 0
                except PermissionError:
                    pass
        elif key == ord(' '):
            item = display_items[cursor_idx]
            if item != "..":
                full_path = os.path.abspath(os.path.join(current_dir, item))
                if full_path in selected_paths:
                    selected_paths.remove(full_path)
                else:
                    selected_paths.add(full_path)
        elif key in (ord('c'), ord('C')):
            return list(selected_paths)
        elif key in (ord('q'), ord('Q')):
            return []


def do_init(stdscr):
    if os.path.exists(MASTER_KEYS_FILE):
        confirm = prompt_input(stdscr, "WARNING: Key file exists! Past files will be unrecoverable! Type 'yes' to overwrite:")
        if confirm.lower() != 'yes':
            return
        os.remove(MASTER_KEYS_FILE)

    pw1 = prompt_input(stdscr, "Enter NEW master password:", is_password=True)
    pw2 = prompt_input(stdscr, "Confirm master password:", is_password=True)
    
    if pw1 != pw2:
        show_message(stdscr, "Passwords do not match!")
        return
        
    if len(pw1) == 0:
        show_message(stdscr, "Password cannot be empty!")
        return
        
    try:
        init_master_file(pw1)
        show_message(stdscr, "Successfully generated master key file and weekly keys.")
    except EKMSCryptoError as e:
        show_message(stdscr, f"Error: {e}")
    except Exception as e:
        show_message(stdscr, f"Unexpected error: {e}")

def do_crypto(stdscr, mode, scrub_enabled):
    paths = file_browser(stdscr, f"Select Files to {mode.capitalize()}")
    if not paths:
        return
        
    password = prompt_input(stdscr, "Enter master password:", is_password=True)
    
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    stdscr.addstr(h//2, max(0, w//2 - 10), "Processing... Please wait.")
    stdscr.refresh()
    
    try:
        keys_dict = load_keys(password)
        keys_dict = ensure_current_year_keys(password, keys_dict)
    except EKMSCryptoError as e:
        show_message(stdscr, f"Error: {e}")
        return
        
    all_files = get_all_files(paths)
    
    if not all_files:
        show_message(stdscr, "No files found to process.")
        return
        
    valid_files = []
    for f in all_files:
        if mode == 'encrypt' and f.endswith('.enc'):
            continue
        if mode == 'decrypt' and not f.endswith('.enc'):
            continue
        valid_files.append(f)
        
    if not valid_files:
        show_message(stdscr, "No valid files found for this operation.")
        return

    # Confirmation screen
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    stdscr.attron(curses.color_pair(1))
    stdscr.addstr(0, max(0, w//2 - 13), " Confirm Files to Process ")
    stdscr.attroff(curses.color_pair(1))
    
    max_display = h - 5
    for i, f in enumerate(valid_files[:max_display]):
        stdscr.addstr(2 + i, 2, f"-> {f}"[:w-4])
        
    if len(valid_files) > max_display:
        stdscr.addstr(2 + max_display, 2, f"... and {len(valid_files) - max_display} more files.")
        
    stdscr.attron(curses.color_pair(3))
    stdscr.addstr(h-1, 0, f" Total Files: {len(valid_files)} | Press ENTER to confirm, or Q to cancel "[:w-1].ljust(w-1))
    stdscr.attroff(curses.color_pair(3))
    
    stdscr.refresh()
    while True:
        key = stdscr.getch()
        if key in (10, 13):
            break
        elif key in (ord('q'), ord('Q')):
            return
        
    success = 0
    errors = 0
    
    current_year = datetime.date.today().year
    current_week = datetime.date.today().isocalendar()[1]
    
    log_messages = []
    
    def update_progress(filepath, phase, processed, total, status=None):
        stdscr.clear()
        
        fname = os.path.basename(filepath)
        if status:
            line = f"[{phase.upper()}] {fname} -> {status}"
            log_messages.append(line)
            active_bar = None
        else:
            bar_width = min(30, max(10, w - 40))
            pct = (processed / total) if total > 0 else 1.0
            filled = int(bar_width * pct)
            empty = bar_width - filled
            bar = f"[{'#' * filled}{'-' * empty}] {int(pct * 100)}%"
            active_bar = f"[{phase.upper()}] {fname} {bar}"
            
        max_logs_to_show = h - 4
        start_idx = max(0, len(log_messages) - max_logs_to_show)
        
        stdscr.attron(curses.color_pair(1))
        stdscr.addstr(0, max(0, w//2 - 7), " Process Log ")
        stdscr.attroff(curses.color_pair(1))
        
        for i, idx in enumerate(range(start_idx, len(log_messages))):
            stdscr.addstr(2 + i, 2, log_messages[idx][:w-4])
            
        if active_bar:
            stdscr.addstr(h - 2, 2, active_bar[:w-4])
            
        stdscr.refresh()

    total_files = len(valid_files)
    for idx, f in enumerate(valid_files, 1):
        try:
            if mode == 'encrypt':
                if f.endswith('.enc'):
                    continue
                week_key_b64 = keys_dict[str(current_year)][current_week - 1]
                week_key_bytes = base64.b64decode(week_key_b64)
                
                encrypt_file(f, week_key_bytes, current_year, current_week,
                             callback=lambda p, t: update_progress(f, "encrypting", p, t))
                update_progress(f, "encrypting", 1, 1, status="SUCCESS")
                
                if scrub_enabled:
                    secure_delete(f, callback=lambda p, t: update_progress(f, "scrubbing", p, t))
                    update_progress(f, "scrubbing", 1, 1, status="SUCCESS")
            else:
                if not f.endswith('.enc'):
                    continue
                decrypt_file(f, keys_dict,
                             callback=lambda p, t: update_progress(f, "decrypting", p, t))
                update_progress(f, "decrypting", 1, 1, status="SUCCESS")
                
                if scrub_enabled:
                    secure_delete(f, callback=lambda p, t: update_progress(f, "scrubbing", p, t))
                    update_progress(f, "scrubbing", 1, 1, status="SUCCESS")
            success += 1
        except Exception as e:
            update_progress(f, "processing", 0, 0, status=f"FAILED ({e})")
            errors += 1
            
    show_message(stdscr, f"Completed.\\nSuccess: {success}\\nErrors: {errors}")

def main_tui(stdscr):
    curses.curs_set(0)
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE) # Title
    curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_CYAN) # Highlight
    curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_BLUE) # Status
    
    options = ["1. Initialize Master File", "2. Encrypt Files", "3. Decrypt Files", "4. Exit"]
    current_row = 0
    scrub_enabled = False
    
    while True:
        draw_menu(stdscr, current_row, options, "Main Menu", scrub_enabled)
        key = stdscr.getch()
        
        if key == curses.KEY_UP and current_row > 0:
            current_row -= 1
        elif key == curses.KEY_DOWN and current_row < len(options) - 1:
            current_row += 1
        elif key in (10, 13):
            if current_row == 0:
                do_init(stdscr)
            elif current_row == 1:
                do_crypto(stdscr, 'encrypt', scrub_enabled)
            elif current_row == 2:
                do_crypto(stdscr, 'decrypt', scrub_enabled)
            elif current_row == 3:
                break
        elif key in (ord('s'), ord('S')):
            scrub_enabled = not scrub_enabled
        elif key in (ord('q'), ord('Q')):
            break

def run_tui():
    curses.wrapper(main_tui)

if __name__ == '__main__':
    run_tui()
