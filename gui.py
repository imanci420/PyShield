import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import json
from github_code_fetcher import analyze_repo

# Global variables for findings and summary
root = None
repo_entry = None
findings_tree = None
summary_text = None
all_findings = []
table_headings = ["Line", "Severity", "Type", "Message"]

# Theme Configuration Functions
def configure_dark_theme(style):
    style.theme_use('clam')
    style.configure('TFrame', background='#333333')
    style.configure('TLabel', background='#333333', foreground='white', font=('Helvetica', 12))
    style.configure('TEntry', background='#1e1e1e', foreground='white', fieldbackground='#1e1e1e', font=('Helvetica', 12))
    style.configure('TButton', background='#4e4e4e', foreground='white', borderwidth=1, font=('Helvetica', 12))
    style.map('TButton', background=[('active', '#5e5e5e'), ('pressed', '#5e5e5e')])

    # Apply dark mode to findings_tree and summary_text
    style.configure('Treeview', background='#1e1e1e', foreground='white', fieldbackground='#1e1e1e', font=('Helvetica', 12))
    style.configure('Treeview.Heading', background='#333333', foreground='white', font=('Helvetica', 12))
    style.configure('TScrolledText', background='#1e1e1e', foreground='white', insertbackground='white', font=('Helvetica', 12))



def configure_light_theme(style):
    style.theme_use('default')
    style.configure('TFrame', background='white')
    style.configure('TLabel', background='white', foreground='black', font=('Helvetica', 12))
    style.configure('TEntry', background='white', foreground='black', fieldbackground='white', font=('Helvetica', 12))
    style.configure('TButton', background='lightgray', foreground='black', borderwidth=1, font=('Helvetica', 12))
    style.map('TButton', background=[('active', 'gray'), ('pressed', 'gray')])

def clear_widgets():
    global findings_tree
    for item in findings_tree.get_children():
        findings_tree.delete(item)

    global summary_text
    if summary_text:
        summary_text.delete(1.0, tk.END)

def handle_scan(repo, check_type):
    clear_widgets()
    findings_data = analyze_repo(repo, check_type)
    
    if findings_data['findings']:
        global all_findings
        all_findings = findings_data['findings']
        for finding in all_findings:
            # Extract data from finding
            line_number = finding.get('line_number')
            severity = finding.get('severity', 'N/A')
            issue_type = finding.get('type')
            message = finding.get('message')
            solution = finding.get('solution', 'No specific solution available.')  # Provide a default message

            # Debug print before inserting into the treeview
            print(f"Debug: Inserting into tree: {finding}")  # Debug print

            # Insert into the treeview
            findings_tree.insert("", "end", values=(line_number, severity, issue_type, message, solution))
    else:
        findings_tree.insert("", "end", values=("No issues found.", "", "", "", ""))

    display_summary(findings_data['summary'], all_findings)


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

def open_settings_window():
    settings_window = tk.Toplevel(root)
    settings_window.title("Settings")
    settings_window.resizable(False, False)

    # Styling for the settings window
    settings_window.configure(background='#f0f0f0')
    header_label = ttk.Label(settings_window, text="Settings", font=("TkDefaultFont", 16))
    header_label.pack(pady=(10, 5))

    description_label = ttk.Label(settings_window, text="Adjust the severity and enable/disable specific checks.", background='#f0f0f0')
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

def show_selected_solution():
    selected_item = findings_tree.selection()
    if selected_item:
        item = findings_tree.item(selected_item)
        print(f"Debug: Selected item values: {item['values']}")  # Debug print
        print("Selected item values:", item['values'])  # Debugging statement
        if len(item['values']) >= 5:  # Check if the solution is present
            solution = item['values'][4]  # Solution is the 5th element
            messagebox.showinfo("Solution", f"Solution: {solution}")
        else:
            messagebox.showwarning("No Solution", "No solution available for this issue.")
    else:
        messagebox.showwarning("No Selection", "Please select an issue to view the solution.")



# GUI Creation Function
def create_gui():
    global root, repo_entry, findings_tree, summary_text

    root = tk.Tk()
    root.title("PyShield")

    style = ttk.Style()
    is_dark_theme = True
    configure_dark_theme(style)
    root.configure(background='#333333')

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

    def toggle_theme():
        nonlocal is_dark_theme
        is_dark_theme = not is_dark_theme
        if is_dark_theme:
            configure_dark_theme(style)
            root.configure(background='#333333')
            # Update summary_text for dark mode
            summary_text.config(background='#1e1e1e', foreground='white', insertbackground='white')
        else:
            configure_light_theme(style)
            root.configure(background='white')
            # Update summary_text for light mode
            summary_text.config(background='white', foreground='black', insertbackground='black')

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

    summary_frame = ttk.LabelFrame(output_frame, text="Summary", padding="10")
    summary_frame.pack(side=tk.LEFT, fill=tk.Y, expand=False)

    summary_text_frame = ttk.Frame(summary_frame)
    summary_text_frame.pack(fill=tk.BOTH, expand=True)

    summary_text = scrolledtext.ScrolledText(summary_text_frame, width=30, height=10, background='#1e1e1e', foreground='white', insertbackground='white', font=('Helvetica', 12))
    summary_text.pack(fill=tk.BOTH, expand=True)

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

    show_solution_button = ttk.Button(findings_frame, text="Show Solution", command=show_selected_solution)
    show_solution_button.pack(pady=5)

    root.mainloop()

    

if __name__ == "__main__":
    create_gui()