import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import json
from github_code_fetcher import analyze_repo
from tkinter import messagebox
import re
import requests



# Global variables for findings and summary
root = None
repo_entry = None
findings_tree = None
summary_text = None
all_findings = []
table_headings = ["Line", "Severity", "Type", "Message"]
is_dark_theme = True

# Theme Configuration Functions
def configure_theme(style, is_dark):
    # Define a set of colors for dark and light themes
    colors = {
        'dark': {
            'frame_bg': '#333333',
            'widget_bg': '#1e1e1e',
            'widget_fg': 'white',
            'button_bg': '#5e5e5e',
            'button_fg': 'white',
            'button_active': '#4e4e4e',
            'text_bg': '#1e1e1e',
            'text_fg': 'white',
        },
  'light': {
            'frame_bg': '#f0f0f0',          # Slightly off-white
            'widget_bg': 'white',
            'widget_fg': 'black',
            'button_bg': 'lightgray',
            'button_fg': 'black',
            'button_active': 'gray',
            'text_bg': 'white',
            'text_fg': 'black',
        }
    }
    theme_colors = colors['dark'] if is_dark else colors['light']

    style.theme_use('alt')
    style.configure('TFrame', background=theme_colors['frame_bg'], borderwidth=2, relief="flat")
    style.configure('TLabel', background=theme_colors['frame_bg'], foreground=theme_colors['widget_fg'], font=('Helvetica', 12), padding=3)
    style.configure('TEntry', background=theme_colors['widget_bg'], foreground=theme_colors['widget_fg'], fieldbackground=theme_colors['widget_bg'], font=('Helvetica', 12), borderwidth=2, relief="flat")
    style.configure('TButton', background=theme_colors['button_bg'], foreground=theme_colors['button_fg'], borderwidth=2, font=('Helvetica', 12), relief="raised", padding=5)
    style.map('TButton', background=[('active', theme_colors['button_active']), ('pressed', '!focus', theme_colors['button_active'])])
    style.configure('Treeview', background=theme_colors['text_bg'], foreground=theme_colors['text_fg'], fieldbackground=theme_colors['text_bg'], font=('Helvetica', 12), relief="flat", borderwidth=2, padding=3)
    style.configure('Treeview.Heading', background=theme_colors['frame_bg'], foreground=theme_colors['widget_fg'], font=('Helvetica', 12), relief="flat", borderwidth=2, padding=3)
    style.configure('TScrolledText', background=theme_colors['text_bg'], foreground=theme_colors['text_fg'], insertbackground=theme_colors['widget_fg'], font=('Helvetica', 12), borderwidth=2, relief="flat", padding=3)
    theme_colors = colors['dark'] if is_dark else colors['light']


def clear_widgets():
    global findings_tree
    for item in findings_tree.get_children():
        findings_tree.delete(item)

    global summary_text
    if summary_text:
        summary_text.delete(1.0, tk.END)

def handle_scan(repo, check_type):
    clear_widgets()

    # Check if the repository name is valid
    if not re.match(r'^[A-Za-z0-9-]+/[A-Za-z0-9-]+$', repo):
        messagebox.showerror("Invalid Repository Name", "Please enter a valid GitHub repository name (e.g., owner/repo).")
        return

    try:
        findings_data = analyze_repo(repo, check_type)
        
        if 'error' in findings_data:
            # Show the error message received from the API
            display_summary.insert("ERROR - Unable to fetch repo contents. Status code: 404")
        else:
            global all_findings
            all_findings = findings_data['findings']
            for finding in all_findings:
                line_number = finding.get('line_number')
                severity = finding.get('severity', 'N/A')
                issue_type = finding.get('type')
                message = finding.get('message')
                solution = finding.get('solution', 'No specific solution available.')
                refactoring = finding.get('refactoring', 'No specific refactoring suggestion available.')  # Include refactoring info
                print(f"Debug: Inserting into tree: Line {line_number}, Type {issue_type}, Refactoring: {refactoring}")

                findings_tree.insert("", "end", values=(line_number, severity, issue_type, message, solution, refactoring))
        
        # Display summary even if no findings are found
        display_summary(findings_data['summary'], all_findings)
    except requests.exceptions.HTTPError as e:
        # Show the exact error message received from the API
        messagebox.showerror("Error", str(e))





def display_summary(findings_summary, all_findings):
    summary_text.delete(1.0, tk.END)
    if not findings_summary:
        summary_text.insert(tk.END, "No issues found.")
        return
    for issue_type, count in findings_summary.items():
        summary_line = f"{issue_type}: {count}\n"
        summary_text.insert(tk.END, summary_line)

def save_config(config):
    with open('config.json', 'w') as config_file:
        json.dump(config, config_file, indent=4)

def save_summary_and_findings():
    """
    Saves the summary and findings to a file.
    """
    global summary_text, all_findings
    summary = summary_text.get("1.0", tk.END)
    findings = all_findings

    filename = filedialog.asksaveasfilename(defaultextension=".txt",
                                            filetypes=[("Text files", "*.txt")])
    if filename:
        with open(filename, "w") as file:
            file.write("Summary:\n")
            file.write(summary)
            file.write("\nFindings:\n")
            for finding in findings:
                file.write(json.dumps(finding) + "\n")        

def open_settings_window():
    settings_window = tk.Toplevel(root)
    settings_window.title("Settings")
    settings_window.resizable(False, False)

    # Styling for the settings window
    settings_window.configure(background='#f0f0f0')
    header_label = ttk.Label(settings_window, text="Settings", font=("TkDefaultFont", 16))
    header_label.pack(pady=(10, 5))

    description_label = ttk.Label(settings_window, text="Adjust the severity and enable/disable specific checks.")
    description_label.pack(fill=tk.X, padx=10)

    # Frame for settings
    settings_frame = ttk.Frame(settings_window, padding="10")
    settings_frame.pack(fill=tk.BOTH, padx=10, pady=5)

    try:
        with open('config.json') as config_file:
            config = json.load(config_file)
    except (FileNotFoundError, json.JSONDecodeError):
        messagebox.showerror("Error", "Failed to load config.json.")
        return
    except KeyError:
        messagebox.showerror("Error", "Invalid format in config.json.")
        return

    if 'security_checks' not in config:
        messagebox.showerror("Error", "No security checks configuration found in config.json.")
        return

    # Dictionary to store variables
    check_vars = {}

    for check, settings in config['security_checks'].items():
        check_frame = ttk.Frame(settings_frame)
        check_frame.pack(fill=tk.X, pady=2)

        enabled_var = tk.BooleanVar(value=settings.get('enabled', True))
        severity_var = tk.StringVar(value=settings.get('severity', 'Low'))

        checkbutton = ttk.Checkbutton(check_frame, text=check, variable=enabled_var)
        checkbutton.pack(side=tk.LEFT, padx=5)

        severity_options = ['Low', 'Medium', 'High']
        severity_menu = ttk.OptionMenu(check_frame, severity_var, settings.get('severity', 'Low'), *severity_options)
        severity_menu.pack(side=tk.RIGHT, padx=5)

        # Store variables in the dictionary
        check_vars[check] = {'enabled_var': enabled_var, 'severity_var': severity_var}

    def save_changes():
        for check, vars in check_vars.items():
            config['security_checks'][check]['enabled'] = vars['enabled_var'].get()
            config['security_checks'][check]['severity'] = vars['severity_var'].get()

        with open('config.json', 'w') as config_file:
            json.dump(config, config_file, indent=4)
        messagebox.showinfo("Settings Saved", "Your changes have been saved.")

    apply_button = ttk.Button(settings_window, text="Apply", command=save_changes)
    apply_button.pack(pady=10)


def treeview_sort_column(tv, col, reverse):
    l = [(tv.set(k, col), k) for k in tv.get_children('')]
    try:
        l.sort(key=lambda t: int(t[0]), reverse=reverse)  # Try sorting as integers
    except ValueError:
        l.sort(reverse=reverse)  # Fallback to sorting as strings

    # Rearrange items in sorted positions
    for index, (val, k) in enumerate(l):
        tv.move(k, '', index)

    # Reverse sort next time
    tv.heading(col, command=lambda _col=col: treeview_sort_column(tv, _col, not reverse))   

def show_troubleshooting():
    selected_item = findings_tree.selection()
    if selected_item:
        item = findings_tree.item(selected_item)
        issue_type = item['values'][2]  # Assuming the issue type is the 3rd element

        # Create a new window for troubleshooting
        troubleshooting_window = tk.Toplevel(root)
        troubleshooting_window.title(f"Troubleshooting - {issue_type}")
        troubleshooting_window.resizable(False, False)

        # Output field
        output_text = scrolledtext.ScrolledText(troubleshooting_window, wrap=tk.WORD, height=10, width=50)
        output_text.pack(padx=10, pady=10)

        # Button to show the solution
        def show_solution():
            solution = item['values'][4]  # Assuming solution is the 5th element
            output_text.delete(1.0, tk.END)  # Clear existing text
            output_text.insert(tk.END, f"Solution:\n{solution}\n\n")

        # Button to show the refactoring suggestion
        def show_refactoring():
            refactoring = item['values'][5]  # Assuming refactoring is the 6th element
            output_text.delete(1.0, tk.END)  # Clear existing text
            output_text.insert(tk.END, f"Refactoring Suggestion:\n{refactoring}")

        solution_button = ttk.Button(troubleshooting_window, text="Show Solution", command=show_solution)
        solution_button.pack(side=tk.LEFT, padx=10, pady=10)

        refactoring_button = ttk.Button(troubleshooting_window, text="Show Refactoring", command=show_refactoring)
        refactoring_button.pack(side=tk.RIGHT, padx=10, pady=10)
    else:
        messagebox.showwarning("No Selection", "Please select an issue to view details.")
       
        



# GUI Creation Function
def create_gui():
    global root, repo_entry, findings_tree, summary_text, is_dark_theme

    root = tk.Tk()
    root.title("PyShield")
    root.geometry("1440x700")
    root.resizable(True, True)

    style = ttk.Style()
    is_dark_theme = True
    configure_theme(style, is_dark_theme)

    # Toggle Theme Function
    def toggle_theme():
        global is_dark_theme
        is_dark_theme = not is_dark_theme
        configure_theme(style, is_dark_theme)
        # Update the root background and summary_text for the chosen theme
        root_bg_color = '#333333' if is_dark_theme else 'white'
        root.configure(background=root_bg_color)
        text_bg_color = '#1e1e1e' if is_dark_theme else 'white'
        text_fg_color = 'white' if is_dark_theme else 'black'
        summary_text.config(background=text_bg_color, foreground=text_fg_color, insertbackground=text_fg_color)

    root.configure(relief="flat")

    main_frame = ttk.Frame(root, padding="10")
    main_frame.pack(fill=tk.BOTH, expand=True)

    # Top frame for inputs and buttons
    top_frame = ttk.Frame(main_frame, padding="10")
    top_frame.pack(fill=tk.X, expand=False)

    input_frame = ttk.Frame(top_frame, padding="10")
    input_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

    ttk.Label(input_frame, text="GitHub Repository:").pack(side=tk.LEFT)
    repo_entry = ttk.Entry(input_frame, width=50)
    repo_entry.pack(side=tk.LEFT, padx=10)

    theme_button = ttk.Button(top_frame, text="Toggle Theme", command=toggle_theme)
    theme_button.pack(side=tk.RIGHT, padx=10)

    settings_button = ttk.Button(top_frame, text="Settings", command=open_settings_window)
    settings_button.pack(side=tk.RIGHT, padx=10)

    security_scan_button = ttk.Button(input_frame, text="Scan for Security Issues", command=lambda: handle_scan(repo_entry.get(), 'security'))
    security_scan_button.pack(side=tk.LEFT, padx=10)

    formatting_check_button = ttk.Button(input_frame, text="Check Code Formatting", command=lambda: handle_scan(repo_entry.get(), 'formatting'))
    formatting_check_button.pack(side=tk.LEFT, padx=10)

    output_frame = ttk.Frame(main_frame, padding="10")
    output_frame.pack(fill=tk.BOTH, expand=True)

    # Summary Frame
    summary_frame = ttk.LabelFrame(output_frame, text="Summary", padding="10")
    summary_frame.pack(side=tk.LEFT, fill=tk.Y, expand=False)

    summary_text = scrolledtext.ScrolledText(summary_frame, width=35,  background='#1e1e1e', foreground='white', insertbackground='white', font=('Helvetica', 12))
    summary_text.pack(fill=tk.BOTH, expand=True)

    # Button Frame below Summary Text
    button_frame = ttk.Frame(summary_frame)
    button_frame.pack(fill=tk.X)

    # Save Summary Button
    save_summary_button = ttk.Button(button_frame, text="Save Summary", command=save_summary_and_findings)
    save_summary_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)

    # Troubleshooting Button
    issue_details_button = ttk.Button(button_frame, text="Troubleshooting", command=show_troubleshooting)
    issue_details_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)

    # Quality Button
    quality_check_button = ttk.Button(input_frame, text="Check Code Quality", 
    command=lambda: handle_scan(repo_entry.get(), 'quality'))
    quality_check_button.pack(side=tk.LEFT, padx=10)

    # Findings frame
    findings_frame = ttk.LabelFrame(output_frame, text="Findings", padding="10")
    findings_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Treeview for findings
    table_headings = ["Line", "Severity", "Type", "Message"]
    findings_tree = ttk.Treeview(findings_frame, columns=table_headings, show="headings", selectmode="browse")

    for heading in table_headings:
        findings_tree.heading(heading, text=heading, command=lambda _col=heading: treeview_sort_column(findings_tree, _col, False))
        findings_tree.column(heading, width=150)

    findings_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Create a sorting function
    def treeview_sort_column(tv, col, reverse):
        l = [(tv.set(k, col), k) for k in tv.get_children('')]
        l.sort(reverse=reverse)

        # Rearrange items in sorted positions
        for index, (val, k) in enumerate(l):
            tv.move(k, '', index)

        # Reverse sort next time
        tv.heading(col, command=lambda: treeview_sort_column(tv, col, not reverse))

    for heading in table_headings:
        findings_tree.heading(heading, text=heading, command=lambda col=heading: treeview_sort_column(findings_tree, col, False))
        findings_tree.column(heading, width=150)

    # Create a vertical scrollbar for the findings_tree
    scrollbar = ttk.Scrollbar(findings_frame, orient="vertical", command=findings_tree.yview)
    findings_tree.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    findings_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)


    root.mainloop()

    

if __name__ == "__main__":
    create_gui() 

