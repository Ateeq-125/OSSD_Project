import tkinter as tk
from tkinter import messagebox, ttk
import sqlite3
import hashlib

DB_NAME = 'user.db'

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("SELECT username, role FROM user")
        return c.fetchall()

def view_users():
    user_listbox.delete(*user_listbox.get_children())
    for idx, user in enumerate(load_users()):
        user_listbox.insert("", "end", iid=idx, values=user)

def delete_user():
    selected = user_listbox.selection()
    if selected:
        username, role = user_listbox.item(selected[0])["values"]
        if role == "Admin":
            messagebox.showerror("Error", "Cannot delete another Admin.")
            return
        with sqlite3.connect(DB_NAME) as conn:
            conn.execute("DELETE FROM user WHERE username=?", (username,))
        messagebox.showinfo("Success", f"User '{username}' deleted.")
        view_users()
    else:
        messagebox.showerror("Error", "No user selected.")

def add_user():
    def save():
        uname = entry_username.get().strip()
        pwd = entry_password.get().strip()
        role = role_var.get()
        if not uname or not pwd or role == "Select":
            messagebox.showerror("Error", "All fields are required.")
            return
        try:
            with sqlite3.connect(DB_NAME) as conn:
                conn.execute("INSERT INTO user (username, password, role) VALUES (?, ?, ?)",
                             (uname, hash_password(pwd), role))
            messagebox.showinfo("Success", "User added successfully.")
            view_users()
            win.destroy()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists.")

    # Window Setup
    win = tk.Toplevel(root)
    win.title("Add New User")
    win.geometry("500x400")
    win.configure(bg="#1c1c1c")
    win.resizable(False, False)

    # Styling
    style = ttk.Style(win)
    style.theme_use("clam")
    style.configure("Dark.TLabel", background="#1c1c1c", foreground="turquoise", font=("Segoe UI", 10))
    style.configure("Dark.TButton", background="#1c1c1c", foreground="turquoise", font=("Segoe UI", 10))
    style.configure("Custom.TEntry", foreground="turquoise", fieldbackground="#302E2E", background="#232222", font=("Segoe UI", 10))
    style.map("Dark.TButton",
              background=[("active", "#2a2a2a")],
              foreground=[("active", "white")])

    # Frame
    frame = ttk.Frame(win, padding=20, style="Dark.TFrame")
    frame.place(relx=0.5, rely=0.5, anchor="center")

    ttk.Label(frame, text="Add New User", style="Dark.TLabel", font=("Segoe UI", 14, "bold")).grid(columnspan=2, pady=10)

    ttk.Label(frame, text="Username:", style="Dark.TLabel").grid(row=1, column=0, sticky="e", padx=10, pady=10)
    entry_username = ttk.Entry(frame, width=30, style="Custom.TEntry")
    entry_username.grid(row=1, column=1, pady=10)

    ttk.Label(frame, text="Password:", style="Dark.TLabel").grid(row=2, column=0, sticky="e", padx=10, pady=10)
    entry_password = ttk.Entry(frame, width=30, show="*", style="Custom.TEntry")
    entry_password.grid(row=2, column=1, pady=10)

    ttk.Label(frame, text="Role:", style="Dark.TLabel").grid(row=3, column=0, sticky="e", padx=10, pady=10)
    role_var = tk.StringVar(value="Select")
    role_menu = tk.OptionMenu(frame, role_var, "Select", "Admin", "Teacher", "Student")
    role_menu.config(width=27, bg="#1c1c1c", fg="turquoise", activebackground="#2a2a2a", relief="flat")
    role_menu["menu"].config(bg="#302E2E", fg="turquoise")
    role_menu.grid(row=3, column=1, pady=10)

    ttk.Button(frame, text="Save", command=save, style="Dark.TButton", width=25).grid(row=4, columnspan=2, pady=15)
    ttk.Button(frame, text="Cancel", command=win.destroy, style="Dark.TButton", width=25).grid(row=5, columnspan=2)

def update_user():
    selected = user_listbox.selection()
    if not selected:
        messagebox.showerror("Error", "No user selected.")
        return

    username, role = user_listbox.item(selected[0])["values"]
    if role == "Admin":
        messagebox.showerror("Error", "Cannot update another Admin.")
        return

    def save():
        new_pwd = entry_password.get().strip()
        new_role = role_var.get()
        if not new_pwd or new_role == "Select":
            messagebox.showerror("Error", "All fields are required.")
            return
        with sqlite3.connect(DB_NAME) as conn:
            conn.execute("UPDATE user SET password=?, role=? WHERE username=?",
                         (hash_password(new_pwd), new_role, username))
        messagebox.showinfo("Success", f"User '{username}' updated.")
        view_users()
        win.destroy()

    # Window Setup
    win = tk.Toplevel(root)
    win.title("Update User")
    win.geometry("500x400")
    win.configure(bg="#1c1c1c")
    win.resizable(False, False)

    # Styling
    style = ttk.Style(win)
    style.theme_use("clam")
    style.configure("Dark.TLabel", background="#1c1c1c", foreground="turquoise", font=("Segoe UI", 10))
    style.configure("Dark.TButton", background="#1c1c1c", foreground="turquoise", font=("Segoe UI", 10))
    style.configure("Custom.TEntry", foreground="turquoise", fieldbackground="#302E2E", background="#232222", font=("Segoe UI", 10))
    style.map("Dark.TButton",
              background=[("active", "#2a2a2a")],
              foreground=[("active", "white")])

    # Frame Layout
    frame = ttk.Frame(win, padding=20, style="Dark.TFrame")
    frame.place(relx=0.5, rely=0.5, anchor="center")

    ttk.Label(frame, text="Update User", style="Dark.TLabel", font=("Segoe UI", 14, "bold")).grid(columnspan=2, pady=10)

    ttk.Label(frame, text=f"Username: {username}", style="Dark.TLabel", font=("Segoe UI", 10, "bold")).grid(row=1, columnspan=2, pady=10)

    ttk.Label(frame, text="New Password:", style="Dark.TLabel").grid(row=2, column=0, sticky="e", padx=10, pady=10)
    entry_password = ttk.Entry(frame, width=30, show="*", style="Custom.TEntry")
    entry_password.grid(row=2, column=1, pady=10)

    ttk.Label(frame, text="New Role:", style="Dark.TLabel").grid(row=3, column=0, sticky="e", padx=10, pady=10)
    role_var = tk.StringVar(value=role)
    role_menu = tk.OptionMenu(frame, role_var, role, "Admin", "Teacher", "Student")
    role_menu.config(width=27, bg="#1c1c1c", fg="turquoise", activebackground="#2a2a2a", relief="flat")
    role_menu["menu"].config(bg="#302E2E", fg="turquoise")
    role_menu.grid(row=3, column=1, pady=10)

    ttk.Button(frame, text="Save", command=save, style="Dark.TButton", width=25).grid(row=4, columnspan=2, pady=15)
    ttk.Button(frame, text="Cancel", command=win.destroy, style="Dark.TButton", width=25).grid(row=5, columnspan=2)

# GUI Setup
root = tk.Tk()
root.title("Admin Dashboard")
root.geometry("800x500")
root.configure(bg="#1c1c1c")

style = ttk.Style()
style.theme_use("clam")
style.configure("TFrame", background="#1c1c1c")
style.configure("TLabel", background="#1c1c1c", foreground="turquoise")
style.configure("TButton", background="#1c1c1c", foreground="turquoise")
style.configure("Treeview", background="#1c1c1c", fieldbackground="#1c1c1c", foreground="turquoise")
style.configure("Treeview.Heading", background="#2a2a2a", foreground="white")

notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True, padx=10, pady=10)

tab_users = ttk.Frame(notebook, style="TFrame")
notebook.add(tab_users, text="User Management")

user_listbox = ttk.Treeview(tab_users, columns=("Username", "Role"), show="headings", height=12)
user_listbox.heading("Username", text="Username")
user_listbox.heading("Role", text="Role")
user_listbox.pack(pady=10, fill="x", padx=10)

btn_frame = ttk.Frame(tab_users, style="TFrame")
btn_frame.pack(pady=10)

ttk.Button(btn_frame, text="Refresh", command=view_users).grid(row=0, column=0, padx=5)
ttk.Button(btn_frame, text="Add", command=add_user).grid(row=0, column=1, padx=5)
ttk.Button(btn_frame, text="Update", command=update_user).grid(row=0, column=2, padx=5)
ttk.Button(btn_frame, text="Delete", command=delete_user).grid(row=0, column=3, padx=5)
ttk.Button(btn_frame, text="Exit", command=root.destroy).grid(row=0, column=4, padx=5)

view_users()
root.mainloop()
