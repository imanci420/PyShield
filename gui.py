import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import json
from github_code_fetcher import analyze_repo

def configure_dark_theme():
    style = ttk.Style()
    style.theme_use('clam')

    # Configure dark colors for the theme
    style.configure('TFrame', background='#333333')
    style.configure('TLabel', background='#333333', foreground='white')
    style.configure('TEntry', background='#1e1e1e', foreground='white', fieldbackground='#1e1e1e')
    style.configure('TButton', background='#4e4e4e', foreground='white', borderwidth=1)
    style.map('TButton', background=[('active', '#5e5e5e'), ('pressed', '#5e5e5e')])
    
    default_bg = '#333333'
    return default_bg

def create_gui():
    root = tk.Tk()
    root.title("Python Code Scanner")

    default_bg = configure_dark_theme()
    root.configure(background=default_bg)

    main_frame = ttk.Frame(root, padding="10")
    main_frame.pack(fill=tk.BOTH, expand=True)

    input_frame = ttk.Frame(main_frame, padding="10")
    input_frame.pack(fill=tk.X, expand=True)
    ttk.Label(input_frame, text="GitHub Repository:").pack(side=tk.LEFT)
    repo_entry = ttk.Entry(input_frame, width=50)
    repo_entry.pack(side=tk.LEFT, padx=10)
    scan_button = ttk.Button(input_frame, text="Scan Repository", command=lambda: handle_scan(repo_entry.get()))
    scan_button.pack(side=tk.LEFT)

    output_frame = ttk.Frame(main_frame, padding="10")
    output_frame.pack(fill=tk.BOTH, expand=True)

    summary_frame = ttk.LabelFrame(output_frame, text="Summary", padding="10", width=200)
    summary_frame.pack(side=tk.LEFT, fill=tk.Y, expand=False)
    summary_text = scrolledtext.ScrolledText(summary_frame, height=10)
    summary_text.pack(fill=tk.BOTH, expand=True)

    findings_frame = ttk.LabelFrame(output_frame, text="Findings", padding="10")
    findings_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    findings_text = scrolledtext.ScrolledText(findings_frame)
    findings_text.pack(fill=tk.BOTH, expand=True)

    def update_findings_display(issue_type, all_findings):
        findings_text.delete(1.0, tk.END)
        for finding in all_findings:
            if finding['type'] == issue_type:
                finding_info = f"Line: {finding['line_number']}, Message: {finding['message']}\n"
                findings_text.insert(tk.END, finding_info)

    def display_summary(findings_summary, all_findings):
        summary_text.delete(1.0, tk.END)
        for issue_type, count in findings_summary.items():
            summary_line = f"{issue_type}: {count}\n"
            lbl = tk.Label(summary_text, text=summary_line, fg="blue", cursor="hand2")
            lbl.pack()
            lbl.bind("<Button-1>", lambda e, it=issue_type: update_findings_display(it, all_findings))

    def handle_scan(repo):
        if repo:
            try:
                findings = analyze_repo(repo)
                findings_text.delete(1.0, tk.END)
                findings_text.insert(tk.END, json.dumps(findings['findings'], indent=4))
                display_summary(findings['summary'], findings['findings'])
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showinfo("Info", "Please enter a repository name.")

    root.mainloop()

if __name__ == "__main__":
    create_gui()