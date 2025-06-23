import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import hashlib

class TeacherDashboard(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.pack(fill="both", expand=True)
        self.configure(bg="#1c1c1c")
        self.selected_question_id = None
        self.selected_username = None
        self.quiz_db = "quiz.db"
        self.user_db = "user.db"

        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure("Dark.TFrame", background="#1c1c1c")
        self.style.configure("Dark.TLabel", background="#1c1c1c", foreground="turquoise", font=("Segoe UI", 10))
        self.style.configure("Dark.TButton", background="#1c1c1c", foreground="turquoise", font=("Segoe UI", 10))
        self.style.configure("Custom.TEntry", foreground="turquoise", fieldbackground="#302E2E", background="#232222", font=("Segoe UI", 10))
        self.style.configure("SectionHeader.TLabel", background="#1c1c1c", foreground="white", font=("Segoe UI", 12, "bold"), padding=5)
        self.style.map("Dark.TButton", background=[("active", "#2a2a2a")], foreground=[("active", "white")])

        self.init_quiz_db()
        self.ensure_marks_column()
        self.create_widgets()
        self.view_questions()
        self.view_students()

    def init_quiz_db(self):
        with sqlite3.connect(self.quiz_db) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS quiz_questions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    question TEXT NOT NULL,
                    option_a TEXT NOT NULL,
                    option_b TEXT NOT NULL,
                    option_c TEXT NOT NULL,
                    option_d TEXT NOT NULL,
                    correct_option TEXT NOT NULL CHECK(correct_option IN ('A', 'B', 'C', 'D'))
                )
            ''')

    def ensure_marks_column(self):
        with sqlite3.connect(self.user_db) as conn:
            c = conn.cursor()
            c.execute("PRAGMA table_info(user)")
            if "marks" not in [col[1] for col in c.fetchall()]:
                c.execute("ALTER TABLE user ADD COLUMN marks INTEGER DEFAULT 0")

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def create_widgets(self):
        main_frame = ttk.Frame(self, padding=10, style="Dark.TFrame")
        main_frame.pack(fill="both", expand=True)

        quiz_frame = ttk.Frame(main_frame, style="Dark.TFrame", padding=10)
        quiz_frame.pack(side="left", fill="both", expand=True, padx=5)

        ttk.Label(quiz_frame, text="📘 Quiz Questions", style="SectionHeader.TLabel").pack(anchor="w", pady=(0, 5))

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Custom.Treeview", background="#1c1c1c", foreground="turquoise", rowheight=25,
                        fieldbackground="#1c1c1c", font=("Segoe UI", 10))
        style.configure("Custom.Treeview.Heading", background="#2a2a2a", foreground="white", font=("Segoe UI", 10, "bold"))
        style.map("Custom.Treeview", background=[('selected', '#444444')], foreground=[('selected', 'white')])

        ttk.Label(quiz_frame, text="Question:", style="Dark.TLabel").pack(anchor="w")
        self.entry_question = ttk.Entry(quiz_frame, width=40, style="Custom.TEntry")
        self.entry_question.pack()

        self.entry_a = self.add_entry_field(quiz_frame, "Option A:")
        self.entry_b = self.add_entry_field(quiz_frame, "Option B:")
        self.entry_c = self.add_entry_field(quiz_frame, "Option C:")
        self.entry_d = self.add_entry_field(quiz_frame, "Option D:")

        self.correct_var = tk.StringVar()
        ttk.Label(quiz_frame, text="Correct Option (A/B/C/D):", style="Dark.TLabel").pack(anchor="w")
        self.entry_correct = ttk.Entry(quiz_frame, textvariable=self.correct_var, width=10, style="Custom.TEntry")
        self.entry_correct.pack()

        btn_frame_q = ttk.Frame(quiz_frame, style="Dark.TFrame")
        btn_frame_q.pack(pady=5)
        ttk.Button(btn_frame_q, text="Add", width=6, command=self.add_question, style="Dark.TButton").grid(row=0, column=0, padx=2)
        ttk.Button(btn_frame_q, text="Edit", width=6, command=self.update_question, style="Dark.TButton").grid(row=0, column=1, padx=2)
        ttk.Button(btn_frame_q, text="Delete", width=6, command=self.delete_question, style="Dark.TButton").grid(row=0, column=2, padx=2)

        self.tree_questions = ttk.Treeview(quiz_frame, columns=("ID", "Question"), show="headings", height=4, style="Custom.Treeview")
        self.tree_questions.heading("ID", text="ID")
        self.tree_questions.heading("Question", text="Question")
        self.tree_questions.column("ID", width=50, anchor="w")
        self.tree_questions.column("Question", width=250, anchor="w")
        self.tree_questions.pack(pady=5)
        self.tree_questions.bind("<<TreeviewSelect>>", self.load_selected_question)

        student_frame = ttk.Frame(main_frame, style="Dark.TFrame", padding=10)
        student_frame.pack(side="right", fill="both", expand=True, padx=5)

        ttk.Label(student_frame, text="👨‍🎓 Student Management", style="SectionHeader.TLabel").pack(anchor="w", pady=(0, 5))

        self.entry_username = self.add_entry_field(student_frame, "Username:", width=30)
        self.entry_marks = self.add_entry_field(student_frame, "Marks:", width=30)

        btn_frame_s = ttk.Frame(student_frame, style="Dark.TFrame")
        btn_frame_s.pack(pady=5)
        ttk.Button(btn_frame_s, text="Edit", width=6, command=self.update_student, style="Dark.TButton").grid(row=0, column=1, padx=2)
        ttk.Button(btn_frame_s, text="Delete", width=6, command=self.delete_student, style="Dark.TButton").grid(row=0, column=2, padx=2)

        self.tree_students = ttk.Treeview(student_frame, columns=("Username", "Marks"), show="headings", height=4, style="Custom.Treeview")
        self.tree_students.heading("Username", text="Username")
        self.tree_students.heading("Marks", text="Marks")
        self.tree_students.column("Username", width=120, anchor="w")
        self.tree_students.column("Marks", width=100, anchor="w")
        self.tree_students.pack(pady=5)
        self.tree_students.bind("<<TreeviewSelect>>", self.load_selected_student)

        ttk.Button(student_frame, text="Clear Fields", command=self.clear_student_fields, style="Dark.TButton").pack(pady=5)

    def add_entry_field(self, master, label, width=40):
        ttk.Label(master, text=label, style="Dark.TLabel").pack(anchor="w")
        entry = ttk.Entry(master, width=width, style="Custom.TEntry")
        entry.pack()
        return entry

    def add_question(self):
        q, a, b, c_, d, correct = self.entry_question.get(), self.entry_a.get(), self.entry_b.get(), self.entry_c.get(), self.entry_d.get(), self.correct_var.get().upper()
        if not all([q, a, b, c_, d, correct]):
            return messagebox.showerror("Error", "Fill all fields.")
        if correct not in ['A', 'B', 'C', 'D']:
            return messagebox.showerror("Error", "Correct option must be A/B/C/D")
        with sqlite3.connect(self.quiz_db) as conn:
            conn.execute("INSERT INTO quiz_questions (question, option_a, option_b, option_c, option_d, correct_option) VALUES (?, ?, ?, ?, ?, ?)",
                         (q, a, b, c_, d, correct))
        self.view_questions()
        self.clear_question_fields()
        messagebox.showinfo("Added", "Question added.")

    def view_questions(self):
        self.tree_questions.delete(*self.tree_questions.get_children())
        with sqlite3.connect(self.quiz_db) as conn:
            for row in conn.execute("SELECT id, question FROM quiz_questions"):
                self.tree_questions.insert("", "end", iid=row[0], values=row)

    def load_selected_question(self, event):
        selected = self.tree_questions.selection()
        if selected:
            self.selected_question_id = selected[0]
            with sqlite3.connect(self.quiz_db) as conn:
                c = conn.cursor()
                c.execute("SELECT question, option_a, option_b, option_c, option_d, correct_option FROM quiz_questions WHERE id=?", (self.selected_question_id,))
                data = c.fetchone()
                if data:
                    self.entry_question.delete(0, tk.END)
                    self.entry_question.insert(0, data[0])
                    self.entry_a.delete(0, tk.END); self.entry_a.insert(0, data[1])
                    self.entry_b.delete(0, tk.END); self.entry_b.insert(0, data[2])
                    self.entry_c.delete(0, tk.END); self.entry_c.insert(0, data[3])
                    self.entry_d.delete(0, tk.END); self.entry_d.insert(0, data[4])
                    self.correct_var.set(data[5])

    def update_question(self):
        if not self.selected_question_id:
            return messagebox.showerror("Error", "No question selected.")
        q, a, b, c_, d, correct = self.entry_question.get(), self.entry_a.get(), self.entry_b.get(), self.entry_c.get(), self.entry_d.get(), self.correct_var.get().upper()
        if not all([q, a, b, c_, d, correct]):
            return messagebox.showerror("Error", "Fill all fields.")
        if correct not in ['A', 'B', 'C', 'D']:
            return messagebox.showerror("Error", "Correct option must be A/B/C/D")
        with sqlite3.connect(self.quiz_db) as conn:
            conn.execute("UPDATE quiz_questions SET question=?, option_a=?, option_b=?, option_c=?, option_d=?, correct_option=? WHERE id=?",
                         (q, a, b, c_, d, correct, self.selected_question_id))
        self.view_questions()
        self.clear_question_fields()
        messagebox.showinfo("Updated", "Question updated.")

    def delete_question(self):
        if not self.selected_question_id:
            return messagebox.showerror("Error", "No question selected.")
        with sqlite3.connect(self.quiz_db) as conn:
            conn.execute("DELETE FROM quiz_questions WHERE id=?", (self.selected_question_id,))
        self.view_questions()
        self.clear_question_fields()
        messagebox.showinfo("Deleted", "Question deleted.")

    def clear_question_fields(self):
        self.selected_question_id = None
        self.entry_question.delete(0, tk.END)
        for e in [self.entry_a, self.entry_b, self.entry_c, self.entry_d]:
            e.delete(0, tk.END)
        self.correct_var.set("")

    def view_students(self):
        self.tree_students.delete(*self.tree_students.get_children())
        with sqlite3.connect(self.user_db) as conn:
            for row in conn.execute("SELECT username, marks FROM user WHERE role='Student'"):
                self.tree_students.insert("", "end", values=row)

    def load_selected_student(self, event):
        selected = self.tree_students.selection()
        if selected:
            values = self.tree_students.item(selected[0])['values']
            if values:
                self.selected_username = values[0]
                self.entry_username.delete(0, tk.END)
                self.entry_username.insert(0, values[0])
                self.entry_marks.delete(0, tk.END)
                self.entry_marks.insert(0, values[1])

    def update_student(self):
        if not self.selected_username:
            return messagebox.showerror("Error", "No student selected.")
        u, m = self.entry_username.get(), self.entry_marks.get()
        try:
            m = int(m)
        except ValueError:
            return messagebox.showerror("Error", "Marks must be number.")
        with sqlite3.connect(self.user_db) as conn:
            conn.execute("UPDATE user SET username=?, marks=? WHERE username=? AND role='Student'", 
                         (u, m, self.selected_username))
        self.view_students()
        self.clear_student_fields()
        messagebox.showinfo("Updated", "Student updated.")

    def delete_student(self):
        if not self.selected_username:
            return messagebox.showerror("Error", "No student selected.")
        with sqlite3.connect(self.user_db) as conn:
            conn.execute("DELETE FROM user WHERE username=? AND role='Student'", (self.selected_username,))
        self.view_students()
        self.clear_student_fields()
        messagebox.showinfo("Deleted", "Student deleted.")

    def clear_student_fields(self):
        self.selected_username = None
        self.entry_username.delete(0, tk.END)
        self.entry_marks.delete(0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Teacher Dashboard")
    root.geometry("900x520")
    app = TeacherDashboard(master=root)
    app.mainloop()
