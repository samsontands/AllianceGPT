# CPDI Q&A App

## Description
The CPDI Q&A App is a Streamlit-based web application that provides a chat interface for users to ask questions and receive answers. It uses the Groq API for generating responses and includes user authentication, chat history, and administrative features.

## Features
- User registration and authentication
- Chat interface for asking questions
- Chat history storage
- Admin view for monitoring all chats
- Integration with Groq API for AI-powered responses

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd cpdi-qa-app
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Set up your Groq API key:
   - Create a `.streamlit/secrets.toml` file in the project root
   - Add your Groq API key to the file:
     ```
     GROQ_API_KEY = "your-api-key-here"
     ```

## Usage

1. Run the Streamlit app:
   ```
   streamlit run app.py
   ```

2. Open your web browser and navigate to the URL provided by Streamlit (usually `http://localhost:8501`).

3. Sign up for a new account or log in with existing credentials.

4. Start chatting and asking questions!


## Dependencies
- streamlit
- sqlite3
- groq
- bcrypt
- pandas

## Security Notes
- Passwords are hashed using bcrypt before being stored in the database.
- The admin account is hardcoded for demonstration purposes. In a production environment, implement a more secure method for admin account creation and management.

## Contributing
Contributions to improve the CPDI Q&A App are welcome. Please feel free to submit pull requests or open issues to discuss proposed changes.

## License
[Specify your license here]
