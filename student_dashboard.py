# Student Dashboard (student_dashboard.py)
import tkinter as tk
from tkinter import messagebox, ttk
import sqlite3

def run_quiz(username):
    def ensure_marks_column():
        with sqlite3.connect("user.db") as conn:
            c = conn.cursor()
            c.execute("PRAGMA table_info(user)")
            if "marks" not in [col[1] for col in c.fetchall()]:
                c.execute("ALTER TABLE user ADD COLUMN marks INTEGER DEFAULT 0")

    def load_questions():
        with sqlite3.connect("quiz.db") as conn:
            return conn.execute("SELECT * FROM quiz_questions").fetchall()

    def check_answer():
        nonlocal current_question, score
        if answer_var.get() == questions[current_question][6]:
            score += 1
        next_question()

    def next_question():
        nonlocal current_question
        current_question += 1
        if current_question < len(questions):
            show_question()
        else:
            with sqlite3.connect('user.db') as conn:
                conn.execute("UPDATE user SET marks = ? WHERE username = ? AND role = 'Student'", (score, username))
            messagebox.showinfo("Quiz Completed", f"Your score: {score}/{len(questions)}")
            root.destroy()

    def show_question():
        q = questions[current_question]
        question_label.config(text=f"Q{current_question+1}: {q[1]}")
        option_a.config(text=f"A. {q[2]}")
        option_b.config(text=f"B. {q[3]}")
        option_c.config(text=f"C. {q[4]}")
        option_d.config(text=f"D. {q[5]}")
        answer_var.set(None)

    ensure_marks_column()
    questions = load_questions()
    current_question = 0
    score = 0

    root = tk.Tk()
    root.title("📝 Student Quiz")
    root.geometry("800x500")
    root.configure(bg="#1c1c1c")

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Dark.TFrame", background="#1c1c1c")
    style.configure("Dark.TLabel", background="#1c1c1c", foreground="turquoise", font=("Segoe UI", 13, "bold"))
    style.configure("Dark.TRadiobutton", background="#1c1c1c", foreground="white", font=("Segoe UI", 11))
    style.configure("Dark.TButton", background="#2a2a2a", foreground="turquoise", font=("Segoe UI", 11, "bold"))
    style.map("Dark.TButton",
              background=[("active", "#333")],
              foreground=[("active", "white")])
    
    style.map("Dark.TRadiobutton",
    background=[("active", "#2a2a2a")],
    foreground=[("active", "white")],
    indicatorcolor=[("active", "white")],
    indicatordiameter=[("selected", 10)])

    frame = ttk.Frame(root, padding=20, style="Dark.TFrame")
    frame.pack(fill="both", expand=True)

    question_label = ttk.Label(frame, text="", style="Dark.TLabel", wraplength=700, anchor="w", justify="left")
    question_label.pack(pady=(10, 20), anchor="w")

    answer_var = tk.StringVar()
    option_a = ttk.Radiobutton(frame, text="", variable=answer_var, value="A", style="Dark.TRadiobutton")
    option_b = ttk.Radiobutton(frame, text="", variable=answer_var, value="B", style="Dark.TRadiobutton")
    option_c = ttk.Radiobutton(frame, text="", variable=answer_var, value="C", style="Dark.TRadiobutton")
    option_d = ttk.Radiobutton(frame, text="", variable=answer_var, value="D", style="Dark.TRadiobutton")

    for widget in [option_a, option_b, option_c, option_d]:
        widget.pack(anchor="w", pady=3)

    ttk.Button(frame, text="✅ Submit Answer", command=check_answer, style="Dark.TButton", width=18).pack(pady=30)

    show_question()
    root.mainloop()
