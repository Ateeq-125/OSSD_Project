import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# --- REGISTRATION WINDOW ---
def open_registration_window():
    reg_win = tk.Toplevel(root)
    reg_win.title("Register New Account")
    reg_win.geometry("800x500")
    reg_win.configure(bg="#1c1c1c")

    # Apply dark styles
    style = ttk.Style()
    style.theme_use('clam')
    style.configure("Dark.TFrame", background="#1c1c1c")
    style.configure("Dark.TLabel", background="#1c1c1c", foreground="turquoise", font=("Segoe UI", 10))
    style.configure("Dark.TButton", background="#1c1c1c", foreground="turquoise", font=("Segoe UI", 10))
    style.configure("Custom.TEntry", foreground="turquoise", fieldbackground="#302E2E", background="#232222", font=("Segoe UI", 10))
    style.map("Dark.TButton", background=[("active", "#2a2a2a")], foreground=[("active", "white")])

    def register_user():
        username = entry_username.get().strip()
        password = entry_password.get().strip()
        role = role_var.get()

        if not username or not password or role == "Select":
            messagebox.showerror("Error", "Please fill all fields.")
            return

        hashed_password = hash_password(password)
        conn = sqlite3.connect('user.db')
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS user (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        ''')
        c.execute("SELECT * FROM user WHERE username=?", (username,))
        if c.fetchone():
            messagebox.showerror("Error", "Username already exists.")
            conn.close()
            return

        c.execute("INSERT INTO user (username, password, role) VALUES (?, ?, ?)",
                  (username, hashed_password, role))
        conn.commit()
        conn.close()
        messagebox.showinfo("Success", "User registered successfully.")
        reg_win.destroy()

    frame = ttk.Frame(reg_win, padding=30, style="Dark.TFrame")
    frame.place(relx=0.5, rely=0.5, anchor="center")

    ttk.Label(frame, text="Register New Account", style="Dark.TLabel", font=("Segoe UI", 14, "bold")).grid(columnspan=2, pady=10)

    ttk.Label(frame, text="Username:", style="Dark.TLabel").grid(row=1, column=0, sticky="e", padx=10, pady=10)
    entry_username = ttk.Entry(frame, width=40, style="Custom.TEntry")
    entry_username.grid(row=1, column=1, pady=10)

    ttk.Label(frame, text="Password:", style="Dark.TLabel").grid(row=2, column=0, sticky="e", padx=10, pady=10)
    entry_password = ttk.Entry(frame, width=40, show="*", style="Custom.TEntry")
    entry_password.grid(row=2, column=1, pady=10)

    ttk.Label(frame, text="Role:", style="Dark.TLabel").grid(row=3, column=0, sticky="e", padx=10, pady=10)
    role_var = tk.StringVar(value="Select")
    role_menu = tk.OptionMenu(frame, role_var, "Select", "Admin", "Teacher", "Student")
    role_menu.config(width=35, bg="#1c1c1c", fg="turquoise", activebackground="#2a2a2a", relief="flat")
    role_menu["menu"].config(bg="#302E2E", fg="turquoise")
    role_menu.grid(row=3, column=1, pady=10)

    ttk.Button(frame, text="Register", command=register_user, style="Dark.TButton").grid(row=4, columnspan=2, pady=15)
    ttk.Button(frame, text="Cancel", command=reg_win.destroy, style="Dark.TButton").grid(row=5, columnspan=2)

# --- LOGIN FUNCTION ---
def login():
    username = entry_username.get()
    password = entry_password.get()
    hashed_password = hash_password(password)

    conn = sqlite3.connect('user.db')
    c = conn.cursor()
    c.execute("SELECT role FROM user WHERE username=? AND password=?", (username, hashed_password))
    result = c.fetchone()
    conn.close()

    if result:
        role = result[0]
        messagebox.showinfo("Login Successful", f"Welcome {username}! Role: {role}")
        root.destroy()
        if role == 'Admin':
            import admin_dashboard
        elif role == 'Teacher':
            from teacher_dashboard import TeacherDashboard
            dash_root = tk.Tk()
            dash_root.title("Teacher Dashboard")
            TeacherDashboard(master=dash_root).mainloop()
        elif role == 'Student':
            import student_dashboard
            student_dashboard.run_quiz(username)
        else:
            messagebox.showerror("Error", "Invalid role assigned.")
    else:
        messagebox.showerror("Login Failed", "Invalid username or password.")

# --- MAIN WINDOW SETUP ---
root = tk.Tk()
root.title("SecureLogin System")
root.geometry("800x500")
root.configure(bg="#1c1c1c")
root.resizable(False, False)

# Global Style
style = ttk.Style()
style.theme_use("clam")
style.configure("Dark.TFrame", background="#1c1c1c")
style.configure("Dark.TLabel", background="#1c1c1c", foreground="turquoise", font=("Segoe UI", 10))
style.configure("Dark.TButton", font=("Segoe UI", 10), background="#1c1c1c", foreground="turquoise")
style.configure("Custom.TEntry", foreground="turquoise", fieldbackground="#302E2E", background="#232222")
style.map("Dark.TButton", background=[("active", "#2a2a2a")], foreground=[("active", "white")])

main_frame = ttk.Frame(root, padding=30, style="Dark.TFrame")
main_frame.place(relx=0.5, rely=0.5, anchor="center")

ttk.Label(main_frame, text="Login", style="Dark.TLabel", font=("Segoe UI", 16, "bold")).grid(columnspan=2, pady=20)

ttk.Label(main_frame, text="Username:", style="Dark.TLabel").grid(row=1, column=0, sticky="e", padx=10, pady=10)
entry_username = ttk.Entry(main_frame, style="Custom.TEntry", width=40)
entry_username.grid(row=1, column=1, pady=10)

ttk.Label(main_frame, text="Password:", style="Dark.TLabel").grid(row=2, column=0, sticky="e", padx=10, pady=10)
entry_password = ttk.Entry(main_frame, style="Custom.TEntry", width=40, show="*")
entry_password.grid(row=2, column=1, pady=10)

ttk.Button(main_frame, text="Login", command=login, style="Dark.TButton", width=20).grid(row=3, columnspan=2, pady=10)
ttk.Button(main_frame, text="Register", command=open_registration_window, style="Dark.TButton", width=20).grid(row=4, columnspan=2, pady=5)
ttk.Button(main_frame, text="Exit", command=root.destroy, style="Dark.TButton", width=20).grid(row=5, columnspan=2, pady=5)

root.mainloop()
