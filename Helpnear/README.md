# HelpNear

A Flask-based web application for connecting people who need help with those who can provide it.

## Features
- User registration and authentication
- Create and manage help requests
- Search for helpers
- User profiles with ratings and reviews
- Real-time status updates

## Setup

1. Clone the repository
2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
4. Initialize the database:
   ```
   python -c "from app import init_db; init_db()"
   ```
5. Run the development server:
   ```
   python app.py
   ```

## Deployment

This application is ready to be deployed to platforms like Heroku or Render. The necessary configuration files (`Procfile`, `runtime.txt`) are already included.

## Environment Variables

Create a `.env` file in the root directory with the following variables:

```
FLASK_APP=app.py
FLASK_ENV=production
SECRET_KEY=your-secret-key-here
```

## License

This project is open source and available under the [MIT License](LICENSE).
