# StudyBox

A **centralized platform** for students to manage academic life efficiently, combining essential tools into one user-friendly dashboard.

---

## **Core Layout**

- **Navigation Bar (Top)**
  - Quick access to main pages and user profile.
- **Dynamic Notification Bar**
  - Displays **important reminders, deadlines, and alerts** in a scrolling/slider format.
  - Examples:
    - “📢 Your assignment is due in 2 days.”
    - “⚠️ Attendance is 60% – catch up!”
- **Dashboard Main Section**
  - Cards for quick navigation to all tools.

---

## **Features**

### **1. Profile Management**

- Create, update, and manage user profile.
- Profile fields:
  - Name, Email, Password (editable).
  - Profile Avatars.

---

### **2. Subject Enrollment**

- Students enroll in subjects for the semester.
- **Other features depend on enrolled subjects.**
- Stores:
  - Subject Name
  - Subject Code
  - Credit Hours (used in GPA calculation).

---

### **3. Assignment & Deadline Tracker**

- Add, edit, and manage assignments.
- Fields:
  - Assignment Title
  - Subject
  - Deadline
  - Priority Level
  - Status: Pending / In Progress / Submitted
- Features:
  - Color-coded **urgency warnings**.
  - Dashboard **countdown for upcoming deadlines**.
- Includes **To-Do List** for smaller tasks (integrated inside this section).

---

### **4. Class Schedule (Auto Timetable)**

- Add class times per subject.
- Generates **clean weekly timetable view**.
- If possible:
  - Export timetable as PDF.
  - Sync with Google Calendar.

---

### **5. Attendance Tracker**

- Track daily attendance for enrolled subjects.
- Calculates:
  - **Attendance percentage per subject.**
  - **Overall attendance.**
- Alerts:
  - Shows in top notification bar if attendance < required %.

---

### **6. GPA Calculator**

- Calculates **GPA for current semester**.
- Also shows:
  - **Predicted GPA** if students score X in pending subjects.
  - **Required grades** to hit target GPA.
- Connected to:
  - **Subject Enrollment** (fetch credit hours automatically).

---

### **7. Quick Notes Section**

- Add short, **lightweight notes** for reminders or study points.
- Accessible from dashboard.

---

### **8. Bookmark Links Page**

- Students can **save important URLs** (like portals, PDFs, study sites).

---

### **9. Dashboard Notifications**

- Persistent **top bar** for:
  - Deadlines.
  - Attendance warnings.
  - GPA reminders.
- Scrolling/slider design for multiple alerts.

---

### **10. Dark Mode**

- Full **light/dark theme toggle** for better UX.

## **Tech Stack**

- **Backend**: Python (Flask)
- **Frontend**: HTML + CSS/Bootstrap + JS
- **Database**: PostgreSQL (Render Free Tier)
- **Deployment**: Render (Backend)

---

click here to > [checkout task division](https://www.notion.so/task-division-259a5961e1fc808abcfad07dd826baa2?pvs=21)

[![View Live](https://img.shields.io/badge/View-Live-brightgreen?style=for-the-badge&logo=render)](https://studybox.onrender.com/)
