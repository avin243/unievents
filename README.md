# University Event Management Platform — v3

Welcome to the **University Event Management Platform**, a comprehensive, backend-driven API with a static frontend for managing college and university events. This platform allows administrators to create and manage events, while students can register for events individually or form internal teams to participate in team-based events.

## Features

- **FastAPI Backend**: High-performance asynchronous API built with Python's FastAPI framework.
- **SQLite Database**: Lightweight, serverless database for easy setup and persistent storage.
- **JWT Authentication**: Secure user authentication and authorization using JSON Web Tokens.
- **Role-Based Access Control (RBAC)**: Distinct permissions and views for `admin` and `student` roles.
- **Event Management**: Create, view, update, and manage various university events.
- **Team Participation System**: Robust handling of team creation, join codes, and team registrations for specific events.
- **Interactive UI**: A built-in static frontend serving dynamic content.
- **Interactive Documentation**: Auto-generated Swagger UI accessible out of the box.

---

## Prerequisites

- **Python**: Version 3.8 or higher is recommended.
- **pip**: Python package installer.

---

## Installation & Setup

1. **Clone the Repository** (or download the source code):
   ```bash
   git clone https://github.com/avin243/unievents.git
   cd college_event_system-main
   ```

2. **Create a Virtual Environment** (Optional but recommended):
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   Install the required Python packages defined in `requirements.txt`:
   ```bash
   pip install -r requirements.txt
   ```

---

## Running the Application

To start the University Event Management server, run the following command in your terminal:

```bash
python event_system.py
```

Upon starting, the script will automatically initialize the SQLite database (`university_events_v3.db`) with default configurations and demo credentials if it doesn't already exist.

---

## Accessing the Platform

Once the server is running, you can access the following:

- **Web Interface**: [http://localhost:8000/](http://localhost:8000/)  
  *Serves the main static frontend application.*
- **API Documentation (Swagger UI)**: [http://localhost:8000/docs](http://localhost:8000/docs)  
  *Explore and test the API endpoints directly from your browser.*
- **Alternative API Docs (ReDoc)**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

### Default Test Credentials (if DB is freshly initialized):
- **Admin**: Email: `admin@university.edu` | Password: `admin123`
- **Student**: Email: `student@university.edu` | Password: `student123`

---

## Project Structure

- `event_system.py`: The core FastAPI application, database initialization, and API endpoints.
- `requirements.txt`: Project dependencies and package versions.
- `static/`: Contains the frontend assets (HTML, JS) served by the backend.
- `styles.css`: Styling rules for the web interface.
- `university_events_v3.db`: The SQLite database (auto-generated on the first run).

---

## License

This project is licensed under the MIT License. Feel free to use and modify it for your educational or institutional needs.
