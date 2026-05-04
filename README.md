# 📋 Feedback Management System

A full-stack web application for managing faculty performance feedback in academic institutions. Supports three role-based user tiers — **Admin**, **Faculty**, and **Student** — with JWT authentication, automated scheduling, and a real-time analytics dashboard.

---

## 🧩 Features

### 👨‍💼 Admin
- Secure login with JWT-based session management
- Add, update, and remove faculty and student accounts
- Automate faculty onboarding and session scheduling
- View aggregated performance analytics across all instructors
- Manage academic periods and feedback windows

### 👨‍🏫 Faculty
- View personal performance metrics across 5+ categories
- Track feedback trends over time via Chart.js dashboard
- Access session history and scheduled classes

### 🎓 Student
- Submit feedback through a passkey-protected form
- Rate faculty across multiple performance dimensions
- One submission per faculty per session (enforced server-side)

---

## 🛠️ Tech Stack

| Layer      | Technology                        |
|------------|-----------------------------------|
| Frontend   | HTML5, CSS3, Vanilla JavaScript   |
| Backend    | Node.js, Express.js               |
| Database   | MongoDB (Mongoose ODM)            |
| Auth       | JWT (JSON Web Tokens)             |
| Charts     | Chart.js                          |

---

## ⚙️ Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) v18+
- [MongoDB](https://www.mongodb.com/) (local or Atlas)
- npm

### 1. Clone the Repository

```bash
git clone https://github.com/MOHAN799S/feedback.git
cd feedback
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Configure Environment Variables

Create a `.env` file in the root directory based on `.env.example`:

```env
PORT=5000
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret_key
JWT_EXPIRES_IN=7d
ADMIN_PASSKEY=your_admin_passkey
```

### 4. Seed the Database (Optional)

```bash
node server/config/seed.js
```

This creates default Admin, Faculty, and Student accounts for testing.

### 5. Start the Server

```bash
# Development
npm run dev

# Production
npm start
```

Server runs at `http://localhost:5000`

---

## 🔐 Authentication & Roles

The system uses **JWT-based role authentication** across three tiers:

| Role    | Access Level                              | Auth Method          |
|---------|-------------------------------------------|----------------------|
| Admin   | Full system control, analytics, user mgmt | JWT + Admin Passkey  |
| Faculty | Personal dashboard, session history       | JWT                  |
| Student | Feedback submission only                  | JWT + Session Passkey|

> Token is stored in `httpOnly` cookies and verified on every protected route via `authMiddleware.js`. Zero privilege escalation incidents recorded during QA.

---

## 📊 Analytics Dashboard

The Faculty Analytics Dashboard is built with **Chart.js** and visualizes:

- Overall performance score per instructor
- Category-wise ratings (Teaching Quality, Communication, Punctuality, etc.)
- Feedback volume over time
- Session-wise performance comparison
- Student response rate per faculty

---

## 🔁 API Endpoints

### Auth
| Method | Endpoint             | Description           |
|--------|----------------------|-----------------------|
| POST   | `/api/auth/login`    | Login (all roles)     |
| POST   | `/api/auth/logout`   | Logout                |

### Admin
| Method | Endpoint                    | Description                  |
|--------|-----------------------------|------------------------------|
| GET    | `/api/admin/faculty`        | Get all faculty               |
| POST   | `/api/admin/faculty`        | Add new faculty               |
| PUT    | `/api/admin/faculty/:id`    | Update faculty info           |
| DELETE | `/api/admin/faculty/:id`    | Remove faculty                |
| GET    | `/api/admin/sessions`       | Get all scheduled sessions    |
| POST   | `/api/admin/sessions`       | Schedule a new session        |

### Student
| Method | Endpoint                    | Description                  |
|--------|-----------------------------|------------------------------|
| POST   | `/api/feedback/submit`      | Submit feedback for a faculty |
| GET    | `/api/feedback/history`     | View own submission history   |

### Faculty
| Method | Endpoint                    | Description                  |
|--------|-----------------------------|------------------------------|
| GET    | `/api/faculty/dashboard`    | Get personal analytics data  |
| GET    | `/api/faculty/sessions`     | Get assigned sessions         |

---

## 🧪 Testing

Roles tested manually via Postman. Test credentials (after seeding):

| Role    | Username          | Password     |
|---------|-------------------|--------------|
| Admin   | admin@college.com | admin123     |
| Faculty | faculty@college.com | faculty123  |
| Student | student@college.com | student123  |

> ⚠️ Change all default credentials before any production use.

---

## 🛡️ Security Highlights

- JWT tokens expire after 7 days and are verified on every request
- Passkey layer on student submission prevents unauthorized feedback
- Admin passkey required in addition to JWT for elevated actions
- Passwords hashed using **bcrypt** before storage
- MongoDB queries use Mongoose validation to prevent injection

---

## 📌 Known Limitations

- No email notifications (planned for future release)
- Frontend uses vanilla HTML/CSS — no component framework
- Single-instance MongoDB (no replica set configured)

---

## 🚀 Future Improvements

- [ ] React.js frontend migration
- [ ] Email alerts for feedback window open/close
- [ ] PDF export of faculty performance reports
- [ ] Mobile-responsive redesign
- [ ] Automated test suite (Jest + Supertest)

---

## 👤 Author

**Sangidi Mohan Lakshman**  
[github.com/MOHAN799S](https://github.com/MOHAN799S) · [linkedin.com/in/mohan-lakshman-sangidi](https://www.linkedin.com/in/mohan-lakshman-sangidi-287322256/) · mohansangidi@gmail.com

