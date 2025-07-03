🎓 Student Database Management System (SDBMS)

A lightweight desktop application built using Python and PyQt5 to manage student records with an intuitive interface, secure authentication, and data export features.

🚀 Features
✅ Add, View, and Delete student records

🔐 Secure Login & Role-Based Access (Admin/Student)

🗃️ Data storage using SQLite

📤 Export all student data to CSV

🖥️ Clean, modern GUI using PyQt5

🧠 Smart dropdowns for Department, Year & Course selection

🧰 Field validation and error handling

🎨 Tooltips, Font Styling, and Icons for enhanced UI/UX

📷 Screenshots
(Add screenshots if you have any — GUI for login, student form, CSV export confirmation, etc.)

🛠️ Tech Stack
Technology	Usage
Python 3.x	Backend Logic
PyQt5	GUI Components
SQLite	Local Database
CSV	Data Export
QSS	UI Styling

🔒 Roles & Authentication
Admin can:

Add/Delete/View Students

Export Data

Student can:

View Student Info

Passwords are securely stored using SHA-256 hashing.

📦 Installation
bash
Copy
Edit
git clone https://github.com/your-username/sdbms.git
cd sdbms
pip install PyQt5
python sdbms.py


📦 Installation
bash
git clone https://github.com/your-username/sdbms.git
cd sdbms
pip install PyQt5
python sdbms.py

📂 Project Structure
├── sdbms.py           # Main application
├── sdms.db            # Auto-created SQLite DB file
├── user.png           # Optional: Icon used in UI
└── README.md
📈 How CSV Export Works
Click on "Export Students to CSV", and a file dialog will open. Select the location and filename. The app will export all records from the database into a readable .csv file.

✨ Future Enhancements
PDF export of individual student details

GUI themes/dark mode

Admin dashboard with statistics

Search & filter capabilities

🤝 Contributing
Contributions are welcome! If you'd like to improve UI/UX or optimize code, feel free to fork the repo and submit a pull request.

📜 License
This project is open-source and available under the MIT License.
