# AllianceGPT — Groq-powered Q&A hub

A lightweight Streamlit app that pairs Groq’s Mixtral completion with a simple SQLite-backed chat experience. It offers user registration, persistent chat history, and a small admin dashboard with analytics, CSV downloads, and user management hooks so you can quickly prototype a private, team-friendly assistant.

## Features

- Register/login flows with bcrypt-hashed credentials (admin account seeded via secrets)
- Persistent chat history stored locally in `chat_app.db`
- Groq chat completions streamed directly into the interface (model: `mixtral-8x7b-32768`)
- Admin dashboard with metrics (daily/hourly query trends, top users), live chat logs, and database download/reset controls
- User deletion utility for cleaning up test accounts from the demo environment

## Tech stack

- [Streamlit](https://streamlit.io/) for UI + state management
- [Groq Realtime API](https://groq.com/) (`Groq` Python client) for LLM responses
- SQLite for lightweight persistence
- Plotly and pandas for analytics charts
- bcrypt for password hashing

## Getting started

### 1. Clone & install

```bash
git clone https://github.com/samsontands/AllianceGPT.git
cd AllianceGPT
pip install -r requirements.txt
```

### 2. Configure secrets

Create a `.streamlit/secrets.toml` file (and keep it outside version control):

```toml
GROQ_API_KEY = "your-groq-api-key"
ADMIN_PASSWORD = "choose-a-secure-admin-password"
```

The app uses `st.secrets` to hydrate both the Groq client and the seeded admin credentials.

### 3. Run the app

```bash
streamlit run groq_streamlit_app.py
```

Streamlit will open `http://localhost:8501` by default.

## Admin notes

- Admin user: `samson tan` (password defined above).
- Admin controls expose a database download button, reset hook, chat log CSV export, and user deletion dropdown.
- `chat_app.db` lives in the project root; keep it out of git by honoring `.gitignore` (provided).
- Use `st.cache_data.clear()` + `st.cache_resource.clear()` from the dashboard to flush cached analytics if you train locally.

## Development

- The Groq client is created in `init_groq_client()` and set to stream completions, so you can watch tokens appear in the UI and reuse the same `client` instance per session.
- Analytics queries rely on the `chats` table; if you need a fresh start, click _Reinitialize Database_ under admin controls.
- Extend `get_top_users()`, `get_mean_daily_query_data()`, and `get_mean_hourly_query_data()` for more dashboards.

## Security & privacy

- Passwords are hashed via bcrypt before storage.
- The public admin username is hardcoded for demo purposes; replace it with a proper onboarding flow before deploying.
- Never commit `.streamlit/secrets.toml` or `chat_app.db` to GitHub. Use environment variables or secret managers in production.

## Contributing

Happy to collaborate! Open an issue with your idea, or send a pull request. Focus areas right now:

- Introduce unit tests for the persistence layer
- Swap SQLite for Postgres (if the app will be multi-user)
- Add role-based access controls beyond the single admin flag

## License

Add your license information (MIT, Apache 2.0, etc.) here.
