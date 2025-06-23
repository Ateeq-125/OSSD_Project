import tkinter as tk
from tkinter import messagebox, ttk
import sqlite3
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

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
    entry_username.delete(0, tk.END)
    entry_password.delete(0, tk.END)
    role_var.set("Select")

# GUI
root = tk.Tk()
root.title("User Registration")
root.geometry("800x500")
root.resizable(False, False)
root.configure(bg="#1c1c1c")

style = ttk.Style()
style.theme_use("clam")
style.configure("TFrame", background="#1c1c1c")
style.configure("TLabel", font=("Segoe UI", 10), background="#1c1c1c", foreground="turquoise")
style.configure("TButton", font=("Segoe UI", 10), background="#1c1c1c", foreground="turquoise")
style.configure("TEntry",
                foreground="turquoise",
                fieldbackground="#302E2E",
                background="#232222", padding=5)

style.map("Dark.TButton",
          background=[("active", "#2a2a2a")],
          foreground=[("active", "white")])

main_frame = ttk.Frame(root, padding=30, style="TFrame")
main_frame.place(relx=0.5, rely=0.5, anchor="center")

ttk.Label(main_frame, text="Register New User", font=("Segoe UI", 16, "bold")).grid(columnspan=2, pady=(0, 20))

ttk.Label(main_frame, text="Username:").grid(row=1, column=0, sticky="e", padx=10, pady=10)
entry_username = ttk.Entry(main_frame,style= "TEntry", width=25)
entry_username.grid(row=1, column=1, pady=10)

ttk.Label(main_frame, text="Password:").grid(row=2, column=0, sticky="e", padx=10, pady=10)
entry_password = ttk.Entry(main_frame,style= "TEntry", width=25,show="*")
entry_password.grid(row=2, column=1, pady=10)

ttk.Label(main_frame, text="Role:").grid(row=3, column=0, sticky="e", padx=10, pady=10)
role_var = tk.StringVar(value="Select")
role_menu = tk.OptionMenu(main_frame, role_var, "Select", "Admin", "Teacher", "Student")
role_menu.config(width=20, bg="#1c1c1c", fg="turquoise", activebackground="gray", relief="flat")
role_menu["menu"].config(bg="#302E2E", fg="turquoise")
role_menu.grid(row=3, column=1, pady=10)

ttk.Button(main_frame, text="Register",style= "Dark.TButton", width=20, command=register_user).grid(row=4, column=1, pady=20, sticky="w")
ttk.Button(main_frame, text="Exit",style= "Dark.TButton", width=20, command=root.destroy).grid(row=5, column=1, sticky="w")

root.mainloop()
