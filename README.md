
# 🎓 Quiz Management System

A role-based quiz management system built with **Python**, **Tkinter**, and **SQLite**. This application provides distinct dashboards for Admins, Teachers, and Students to manage users, create and evaluate quizzes, and view performance.

## 📂 Project Structure

- `register.py` – User registration GUI
- `admin_dashboard.py` – Admin panel for user account management
- `teacher_dashboard.py` – Teacher panel for quiz and student marks management
- `student_dashboard.py` – Quiz interface for students
- `user.db` – SQLite database for user accounts
- `quiz.db` – SQLite database for quiz questions

## 🔐 Features by Role

### 👨‍💼 Admin
- Add, update, and delete **users** (Admins cannot modify other Admins)
- View all registered users

### 👩‍🏫 Teacher
- Add, update, delete, and view **quiz questions**
- View and update **student marks**
- Manage student accounts (Edit/Delete)

### 👨‍🎓 Student
- Take the quiz
- Automatically saves marks to database

## 🧠 Quiz Format
Each question has:
- One correct option (A/B/C/D)
- Stored in `quiz.db` under the `quiz_questions` table

## 📌 Database Schema

### `user.db` (`user` table)
| Column     | Type    | Description           |
|------------|---------|-----------------------|
| username   | TEXT    | Unique user ID        |
| password   | TEXT    | SHA-256 hashed string |
| role       | TEXT    | Admin/Teacher/Student |
| marks      | INTEGER | Student score         |

### `quiz.db` (`quiz_questions` table)
| Column        | Type    | Description                  |
|---------------|---------|------------------------------|
| id            | INTEGER | Primary key                  |
| question      | TEXT    | Quiz question                |
| option_a..d   | TEXT    | Answer choices               |
| correct_option| TEXT    | A/B/C/D                      |

## 💻 Technologies Used

- Python 3
- Tkinter for GUI
- SQLite for database
- hashlib for password security

## 🚀 Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/quiz-management-system.git
   cd quiz-management-system
   ```

2. Run `register.py` to create users:
   ```bash
   python register.py
   ```

3. Launch dashboards based on role:
   - Admin: `python admin_dashboard.py`
   - Teacher: `python teacher_dashboard.py`
   - Student: `python student_dashboard.py`

## 🛠 Future Improvements

- Add login screen with role-based redirection
- Add quiz timer
- Export results to CSV or PDF
- Password recovery/reset features

## 📄 License

MIT License

---

Created by [Ateeq ur Rehman]
