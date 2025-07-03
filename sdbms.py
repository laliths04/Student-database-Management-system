import sys, sqlite3, time, csv, hashlib
from PyQt5 import QtGui, QtCore
from PyQt5.QtWidgets import (
    QTableWidgetItem, QTableWidget, QComboBox, QVBoxLayout, QGridLayout, QDialog,
    QWidget, QPushButton, QApplication, QMainWindow, QMessageBox, QLabel,
    QLineEdit, QFileDialog, QHBoxLayout
)
from PyQt5.QtCore import Qt

current_user_role = None  # Global logged-in user role
current_username = None  # To display logged in user


class DBHelper():
    def __init__(self):
        self.conn = sqlite3.connect("sdms.db", check_same_thread=False)
        self.c = self.conn.cursor()
        self.c.execute("""
            CREATE TABLE IF NOT EXISTS student(
                sid INTEGER PRIMARY KEY,
                Sname TEXT,P
                dept INTEGER,
                year INTEGER,
                course_a INTEGER,
                course_b INTEGER,
                course_c INTEGER
            )
        """)
        self.c.execute("""
            CREATE TABLE IF NOT EXISTS users(
                username TEXT PRIMARY KEY,
                password TEXT,
                role TEXT
            )
        """)
        self.conn.commit()

    def addStudent(self, sid, Sname, dept, year, course_a, course_b, course_c):
        try:
            self.c.execute("INSERT INTO student(sid, Sname, dept, year, course_a, course_b, course_c) VALUES (?, ?, ?, ?, ?, ?, ?)",
                           (sid, Sname, dept, year, course_a, course_b, course_c))
            self.conn.commit()
            QMessageBox.information(None, 'Success', 'Student added successfully.')
        except sqlite3.IntegrityError:
            QMessageBox.warning(None, 'Error', 'Roll number already exists.')
        except Exception as e:
            QMessageBox.warning(None, 'Error', f'Failed to add student: {e}')

    def searchStudent(self, sid):
        self.c.execute("SELECT * FROM student WHERE sid=?", (sid,))
        data = self.c.fetchone()
        if not data:
            QMessageBox.warning(None, 'Not Found', f'No student found with roll no {sid}')
            return None
        return data

    def deleteRecord(self, sid):
        if current_user_role != "admin":
            QMessageBox.warning(None, 'Permission Denied', 'Only admin can delete student records.')
            return
        self.c.execute("DELETE FROM student WHERE sid=?", (sid,))
        self.conn.commit()
        QMessageBox.information(None, 'Success', f'Student with roll no {sid} deleted.')

    def fetchAllStudents(self):
        self.c.execute("SELECT * FROM student")
        return self.c.fetchall()

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def validateUser(self, username, password):
        hashed = self.hash_password(password)
        self.c.execute("SELECT role FROM users WHERE username=? AND password=?", (username, hashed))
        row = self.c.fetchone()
        return row[0] if row else None

    def registerDefaultUser(self):
        self.c.execute("SELECT * FROM users WHERE username='admin'")
        if not self.c.fetchone():
            default_hashed = self.hash_password("admin")
            self.c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("admin", default_hashed, "admin"))
            self.conn.commit()

    def registerNewUser(self, username, password, role="student"):
        try:
            hashed = self.hash_password(password)
            self.c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed, role))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False


class Login(QDialog):
    def __init__(self):
        super().__init__()
        self.db = DBHelper()
        self.db.registerDefaultUser()

        self.setWindowTitle("Login")
        self.setFixedSize(350, 180)

        layout = QVBoxLayout()

        title = QLabel("Student DBMS Login")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 20px; font-weight: bold; margin-bottom: 15px;")
        layout.addWidget(title)

        form_layout = QGridLayout()

        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username")

        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter password")

        form_layout.addWidget(self.username_label, 0, 0)
        form_layout.addWidget(self.username_input, 0, 1)
        form_layout.addWidget(self.password_label, 1, 0)
        form_layout.addWidget(self.password_input, 1, 1)

        layout.addLayout(form_layout)

        btn_layout = QHBoxLayout()
        self.login_btn = QPushButton("Login")
        self.login_btn.clicked.connect(self.handleLogin)
        self.register_btn = QPushButton("Register")
        self.register_btn.clicked.connect(self.openRegister)

        btn_layout.addWidget(self.login_btn)
        btn_layout.addWidget(self.register_btn)

        layout.addLayout(btn_layout)

        self.setLayout(layout)

    def handleLogin(self):
        global current_user_role, current_username
        username = self.username_input.text().strip()
        password = self.password_input.text()
        if not username or not password:
            QMessageBox.warning(self, "Input Error", "Please enter both username and password.")
            return
        role = self.db.validateUser(username, password)
        if role:
            current_user_role = role
            current_username = username
            self.accept()
        else:
            QMessageBox.warning(self, "Login Failed", "Invalid username or password.")

    def openRegister(self):
        reg = Register(self.db)
        reg.exec()


class Register(QDialog):
    def __init__(self, db):
        super().__init__()
        self.db = db

        self.setWindowTitle("Register New User")
        self.setFixedSize(350, 220)  # Slightly taller for role dropdown

        layout = QVBoxLayout()

        title = QLabel("Register New User")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 20px; font-weight: bold; margin-bottom: 15px;")
        layout.addWidget(title)

        form_layout = QGridLayout()

        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Choose a username")

        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Choose a password")

        self.role_label = QLabel("Role:")
        self.role_combo = QComboBox()
        self.role_combo.addItems(["student", "admin"])  # Add more roles if needed

        form_layout.addWidget(self.username_label, 0, 0)
        form_layout.addWidget(self.username_input, 0, 1)
        form_layout.addWidget(self.password_label, 1, 0)
        form_layout.addWidget(self.password_input, 1, 1)
        form_layout.addWidget(self.role_label, 2, 0)
        form_layout.addWidget(self.role_combo, 2, 1)

        layout.addLayout(form_layout)

        self.register_btn = QPushButton("Register")
        self.register_btn.clicked.connect(self.registerUser)
        layout.addWidget(self.register_btn)

        self.setLayout(layout)

    def registerUser(self):
        user = self.username_input.text().strip()
        pw = self.password_input.text()
        role = self.role_combo.currentText()  # Get selected role
        if not user or not pw:
            QMessageBox.warning(self, "Input Error", "Please enter both username and password.")
            return
        success = self.db.registerNewUser(user, pw, role)  # Pass role here
        if success:
            QMessageBox.information(self, "Success", f"User registered successfully as {role}!")
            self.accept()
        else:
            QMessageBox.warning(self, "Error", "Username already exists.")



class AddStudent(QDialog):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Add Student Details")
        self.setFixedSize(400, 400)

        layout = QVBoxLayout()
        form_layout = QGridLayout()

        self.rollLabel = QLabel("Roll No:")
        self.nameLabel = QLabel("Name:")
        self.yearLabel = QLabel("Year:")
        self.branchLabel = QLabel("Department:")
        self.cALabel = QLabel("Slot A:")
        self.cBLabel = QLabel("Slot B:")
        self.cCLabel = QLabel("Slot C:")

        self.rollText = QLineEdit()
        self.rollText.setPlaceholderText("Enter roll number (integer)")
        self.nameText = QLineEdit()
        self.nameText.setPlaceholderText("Enter student name")

        self.yearCombo = QComboBox()
        self.yearCombo.addItems(["1st", "2nd", "3rd", "4th"])

        self.branchCombo = QComboBox()
        self.branchCombo.addItems([
            "Mechanical Engineering", "Chemical Engineering", "Software Engineering",
            "Biotech Engineering", "Computer Science and Engineering", "Information Technology" ,"Artificial Intelligence and Data Science"
        ])

        courses = [
            "DBMS", "OS", "CN", "C++", "JAVA", "PYTHON", "NEURAL NETWORK", "MACHINE LEARNING",
            "CELLS", "DS", "WEB APPLICATION", "MICROBES", "FERTILIZER", "NLP", "MOBILE APP"
        ]

        self.cACombo = QComboBox()
        self.cACombo.addItems(courses)

        self.cBCombo = QComboBox()
        self.cBCombo.addItems(courses)

        self.cCCombo = QComboBox()
        self.cCCombo.addItems(courses)

        form_layout.addWidget(self.rollLabel, 0, 0)
        form_layout.addWidget(self.rollText, 0, 1)
        form_layout.addWidget(self.nameLabel, 1, 0)
        form_layout.addWidget(self.nameText, 1, 1)
        form_layout.addWidget(self.yearLabel, 2, 0)
        form_layout.addWidget(self.yearCombo, 2, 1)
        form_layout.addWidget(self.branchLabel, 3, 0)
        form_layout.addWidget(self.branchCombo, 3, 1)
        form_layout.addWidget(self.cALabel, 4, 0)
        form_layout.addWidget(self.cACombo, 4, 1)
        form_layout.addWidget(self.cBLabel, 5, 0)
        form_layout.addWidget(self.cBCombo, 5, 1)
        form_layout.addWidget(self.cCLabel, 6, 0)
        form_layout.addWidget(self.cCCombo, 6, 1)

        layout.addLayout(form_layout)

        btn_layout = QHBoxLayout()
        self.btnAdd = QPushButton("Add")
        self.btnAdd.clicked.connect(self.addStudent)
        self.btnReset = QPushButton("Reset")
        self.btnReset.clicked.connect(self.reset)
        self.btnCancel = QPushButton("Cancel")
        self.btnCancel.clicked.connect(self.reject)

        btn_layout.addWidget(self.btnAdd)
        btn_layout.addWidget(self.btnReset)
        btn_layout.addWidget(self.btnCancel)

        layout.addLayout(btn_layout)

        self.setLayout(layout)

    def reset(self):
        self.rollText.clear()
        self.nameText.clear()
        self.yearCombo.setCurrentIndex(0)
        self.branchCombo.setCurrentIndex(0)
        self.cACombo.setCurrentIndex(0)
        self.cBCombo.setCurrentIndex(0)
        self.cCCombo.setCurrentIndex(0)

    def addStudent(self):
        try:
            sid = int(self.rollText.text())
        except ValueError:
            QMessageBox.warning(self, "Input Error", "Roll number must be an integer.")
            return

        sname = self.nameText.text().strip()
        if not sname:
            QMessageBox.warning(self, "Input Error", "Student name cannot be empty.")
            return

        year = self.yearCombo.currentIndex()
        dept = self.branchCombo.currentIndex()
        course_a = self.cACombo.currentIndex()
        course_b = self.cBCombo.currentIndex()
        course_c = self.cCCombo.currentIndex()

        db = DBHelper()
        db.addStudent(sid, sname, dept, year, course_a, course_b, course_c)
        self.accept()


def showStudent(data):
    if not data:
        return

    sid, sname, dept_i, year_i, ca_i, cb_i, cc_i = data

    depts = [
            "Mechanical Engineering", "Chemical Engineering", "Software Engineering",
            "Biotech Engineering", "Computer Science and Engineering", "Information Technology" ,"Artificial Intelligence and Data Science"
        ]

    years = ["1st", "2nd", "3rd", "4th"]

    courses = [
            "DBMS", "OS", "CN", "C++", "JAVA", "PYTHON", "NEURAL NETWORK", "MACHINE LEARNING",
            "CELLS", "DS", "WEB APPLICATION", "MICROBES", "FERTILIZER", "NLP", "MOBILE APP"
        ]

    dept = depts[dept_i] if 0 <= dept_i < len(depts) else "Unknown"
    year = years[year_i] if 0 <= year_i < len(years) else "Unknown"
    course_a = courses[ca_i] if 0 <= ca_i < len(courses) else "Unknown"
    course_b = courses[cb_i] if 0 <= cb_i < len(courses) else "Unknown"
    course_c = courses[cc_i] if 0 <= cc_i < len(courses) else "Unknown"

    dialog = QDialog()
    dialog.setWindowTitle("Student Details")
    dialog.setFixedSize(350, 320)

    layout = QVBoxLayout()

    def make_label(text):
        lbl = QLabel(text)
        lbl.setStyleSheet("font-size: 14px; margin: 5px 0;")
        return lbl

    layout.addWidget(make_label(f"Roll No: {sid}"))
    layout.addWidget(make_label(f"Name: {sname}"))
    layout.addWidget(make_label(f"Department: {dept}"))
    layout.addWidget(make_label(f"Year: {year}"))
    layout.addWidget(make_label(f"Slot A: {course_a}"))
    layout.addWidget(make_label(f"Slot B: {course_b}"))
    layout.addWidget(make_label(f"Slot C: {course_c}"))

    btn_close = QPushButton("Close")
    btn_close.clicked.connect(dialog.accept)
    layout.addWidget(btn_close, alignment=Qt.AlignCenter)

    dialog.setLayout(layout)
    dialog.exec()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Student Database Management System")
        self.setFixedSize(480, 320)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        # Welcome + user role display
        self.labelWelcome = QLabel(f"Welcome, {current_username} ({current_user_role})")
        self.labelWelcome.setAlignment(Qt.AlignCenter)
        self.labelWelcome.setStyleSheet("font-size: 16px; font-weight: bold; margin-bottom: 15px;")
        layout.addWidget(self.labelWelcome)

        # Buttons layout
        btn_layout = QGridLayout()
        btn_layout.setSpacing(15)

        self.btnAddStudent = QPushButton("Add Student")
        self.btnAddStudent.clicked.connect(self.openAddStudent)

        self.btnSearchStudent = QPushButton("Search Student")
        self.btnSearchStudent.clicked.connect(self.openSearchStudentDialog)

        self.btnDeleteStudent = QPushButton("Delete Student")
        self.btnDeleteStudent.clicked.connect(self.openDeleteStudentDialog)
        if current_user_role != "admin":
            self.btnDeleteStudent.setEnabled(False)

        self.btnExportCSV = QPushButton("Export All to CSV")
        self.btnExportCSV.clicked.connect(self.exportToCSV)

        self.btnLogout = QPushButton("Logout")
        self.btnLogout.clicked.connect(self.logout)

        btn_layout.addWidget(self.btnAddStudent, 0, 0)
        btn_layout.addWidget(self.btnSearchStudent, 0, 1)
        btn_layout.addWidget(self.btnDeleteStudent, 1, 0)
        btn_layout.addWidget(self.btnExportCSV, 1, 1)
        btn_layout.addWidget(self.btnLogout, 2, 0, 1, 2)

        layout.addLayout(btn_layout)

        # Search dialogs init
        self.initDialogs()

    def initDialogs(self):
        # Search Student Dialog
        self.searchDialog = QDialog(self)
        self.searchDialog.setWindowTitle("Search Student")
        self.searchDialog.setFixedSize(300, 150)
        layout = QVBoxLayout()

        lbl = QLabel("Enter Roll Number to search:")
        self.searchInput = QLineEdit()
        self.searchInput.setPlaceholderText("Roll Number")
        self.searchInput.setValidator(QtGui.QIntValidator())

        btnSearch = QPushButton("Search")
        btnSearch.clicked.connect(self.searchStudent)

        layout.addWidget(lbl)
        layout.addWidget(self.searchInput)
        layout.addWidget(btnSearch)

        self.searchDialog.setLayout(layout)

        # Delete Student Dialog
        self.deleteDialog = QDialog(self)
        self.deleteDialog.setWindowTitle("Delete Student")
        self.deleteDialog.setFixedSize(300, 150)
        layout_del = QVBoxLayout()

        lbl_del = QLabel("Enter Roll Number to delete:")
        self.deleteInput = QLineEdit()
        self.deleteInput.setPlaceholderText("Roll Number")
        self.deleteInput.setValidator(QtGui.QIntValidator())

        btnDelete = QPushButton("Delete")
        btnDelete.clicked.connect(self.deleteStudent)

        layout_del.addWidget(lbl_del)
        layout_del.addWidget(self.deleteInput)
        layout_del.addWidget(btnDelete)

        self.deleteDialog.setLayout(layout_del)

    def openAddStudent(self):
        dlg = AddStudent()
        dlg.exec()

    def openSearchStudentDialog(self):
        self.searchInput.clear()
        self.searchDialog.exec()

    def searchStudent(self):
        sid_text = self.searchInput.text()
        if not sid_text:
            QMessageBox.warning(self, "Input Error", "Please enter a roll number to search.")
            return
        sid = int(sid_text)
        db = DBHelper()
        data = db.searchStudent(sid)
        if data:
            showStudent(data)
            self.searchDialog.accept()

    def openDeleteStudentDialog(self):
        self.deleteInput.clear()
        self.deleteDialog.exec()

    def deleteStudent(self):
        if current_user_role != "admin":
            QMessageBox.warning(self, "Permission Denied", "Only admin can delete students.")
            return
        sid_text = self.deleteInput.text()
        if not sid_text:
            QMessageBox.warning(self, "Input Error", "Please enter a roll number to delete.")
            return
        sid = int(sid_text)
        db = DBHelper()
        db.deleteRecord(sid)
        self.deleteDialog.accept()

    def exportToCSV(self):
        db = DBHelper()
        students = db.fetchAllStudents()
        if not students:
            QMessageBox.information(self, "Info", "No student data to export.")
            return
        filename, _ = QFileDialog.getSaveFileName(self, "Save CSV", "", "CSV files (*.csv)")
        if filename:
            try:
                with open(filename, "w", newline="") as file:
                    writer = csv.writer(file)
                    writer.writerow(["Roll No", "Name", "Department", "Year", "Slot A", "Slot B", "Slot C"])
                    depts = [
                        "Mechanical Engineering", "Chemical Engineering", "Software Engineering",
                        "Biotech Engineering", "Computer Science and Engineering", "Information Technology","Artificial Intelligence and Data Science"
                    ]
                    years = ["1st", "2nd", "3rd", "4th"]
                    courses = [
                        "DBMS", "OS", "CN", "C++", "JAVA", "PYTHON", "DATA SCIENCE", "MACHINE LEARNING",
                        "CELLS", "DS", "NEURAL NETWORKS", "NLP", "FERTILIZER", "PLANTS", "MOBILE APP"
                    ]
                    for s in students:
                        sid, sname, dept_i, year_i, ca_i, cb_i, cc_i = s
                        dept = depts[dept_i] if 0 <= dept_i < len(depts) else "Unknown"
                        year = years[year_i] if 0 <= year_i < len(years) else "Unknown"
                        ca = courses[ca_i] if 0 <= ca_i < len(courses) else "Unknown"
                        cb = courses[cb_i] if 0 <= cb_i < len(courses) else "Unknown"
                        cc = courses[cc_i] if 0 <= cc_i < len(courses) else "Unknown"
                        writer.writerow([sid, sname, dept, year, ca, cb, cc])
                QMessageBox.information(self, "Success", "Data exported successfully.")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to export data: {e}")

    def logout(self):
        global current_user_role, current_username
        current_user_role = None
        current_username = None
        self.close()
        main()


def main():
    app = QApplication(sys.argv)
    login = Login()
    if login.exec() == QDialog.Accepted:
        window = MainWindow()
        window.show()
        sys.exit(app.exec())
    else:
        sys.exit()


if __name__ == "__main__":
    main()
