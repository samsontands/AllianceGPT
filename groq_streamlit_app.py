import streamlit as st
import sqlite3
from groq import Groq
import bcrypt
from datetime import datetime, timedelta
import pandas as pd
import random
import pytz
import plotly.graph_objects as go

# Set the time zone to GMT+8 (Malaysia)
malaysia_tz = pytz.timezone('Asia/Kuala_Lumpur')

# Database setup
def init_db():
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, is_admin INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS chats
                 (id INTEGER PRIMARY KEY, user_id INTEGER, message TEXT, role TEXT, timestamp TEXT)''')
    
    # Check if admin exists, if not, create the fixed admin account
    c.execute("SELECT * FROM users WHERE username=?", ('samson tan',))
    if not c.fetchone():
        hashed_password = bcrypt.hashpw('117853'.encode('utf-8'), bcrypt.gensalt())
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                  ('samson tan', hashed_password, 1))
    
    conn.commit()
    conn.close()

# User authentication
def authenticate(username, password):
    if not username or not password:
        return None
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()
    if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
        return user
    return None

# User registration
def register_user(username, password):
    if not username or not password:
        return False
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
                  (username, hashed_password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

# Save chat message
def save_chat_message(user_id, message, role):
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    timestamp = datetime.now(malaysia_tz).strftime('%Y-%m-%d %H:%M:%S')
    c.execute("INSERT INTO chats (user_id, message, role, timestamp) VALUES (?, ?, ?, ?)",
              (user_id, message, role, timestamp))
    conn.commit()
    conn.close()

# Get user's chat history
def get_user_chats(user_id):
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    c.execute("SELECT message, role FROM chats WHERE user_id=? ORDER BY timestamp DESC", (user_id,))
    chats = c.fetchall()
    conn.close()
    return [{"role": role, "content": message} for message, role in chats]

# Function to get mean daily query data for all time (user messages only)
def get_mean_daily_query_data():
    conn = sqlite3.connect('chat_app.db')
    query = """
    SELECT 
        strftime('%w', timestamp) as day_of_week,
        COUNT(*) * 1.0 / (
            SELECT COUNT(DISTINCT DATE(timestamp))
            FROM chats
            WHERE role = 'user'
        ) as mean_query_count
    FROM chats
    WHERE role = 'user'
    GROUP BY day_of_week
    ORDER BY day_of_week
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    
    # Ensure all days are represented
    all_days = pd.DataFrame({'day_of_week': [str(i) for i in range(7)]})
    df = pd.merge(all_days, df, on='day_of_week', how='left').fillna(0)
    df['mean_query_count'] = df['mean_query_count'].astype(float)
    df['day_name'] = df['day_of_week'].map({
        '0': 'Sunday', '1': 'Monday', '2': 'Tuesday', '3': 'Wednesday',
        '4': 'Thursday', '5': 'Friday', '6': 'Saturday'
    })
    
    return df

# Get all chats (for admin)
def get_all_chats():
    conn = sqlite3.connect('chat_app.db')
    query = """
    SELECT users.username, chats.message, chats.role, chats.timestamp 
    FROM chats 
    JOIN users ON chats.user_id = users.id 
    ORDER BY chats.timestamp
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    
    # Convert timestamp to Malaysia time
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='%Y-%m-%d %H:%M:%S')
    df['timestamp'] = df['timestamp'].dt.tz_localize(malaysia_tz)
    df['timestamp'] = df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
    
    return df

# Convert DataFrame to CSV
def convert_df_to_csv(df):
    return df.to_csv(index=False).encode('utf-8')

# Initialize Groq client
def init_groq_client():
    try:
        api_key = st.secrets["GROQ_API_KEY"]
        return Groq(api_key=api_key)
    except Exception as e:
        st.error(f"Error initializing Groq client: {str(e)}")
        return None

# Function to get user statistics
def get_user_stats():
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    
    # Total number of users
    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0]
    
    # Number of users who have used the chat in the last 24 hours
    yesterday = (datetime.now(malaysia_tz) - timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')
    c.execute("SELECT COUNT(DISTINCT user_id) FROM chats WHERE timestamp > ?", (yesterday,))
    active_users_24h = c.fetchone()[0]
    
    # Total number of chat messages
    c.execute("SELECT COUNT(*) FROM chats")
    total_messages = c.fetchone()[0]
    
    conn.close()
    return total_users, active_users_24h, total_messages

# Function to get current active users (placeholder)
def get_current_active_users():
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    
    # Get the timestamp for 1 hour ago
    one_hour_ago = (datetime.now(malaysia_tz) - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
    
    # Count distinct users who have sent a message in the last hour
    c.execute("SELECT COUNT(DISTINCT user_id) FROM chats WHERE timestamp > ?", (one_hour_ago,))
    active_users = c.fetchone()[0]
    
    conn.close()
    return active_users

# Function to get top users
def get_top_users(limit=5):
    conn = sqlite3.connect('chat_app.db')
    query = """
    SELECT users.username, COUNT(chats.id) as message_count
    FROM users
    LEFT JOIN chats ON users.id = chats.user_id
    GROUP BY users.id
    ORDER BY message_count DESC
    LIMIT ?
    """
    df = pd.read_sql_query(query, conn, params=(limit,))
    conn.close()
    return df

# Function to get mean hourly query data for all time
def get_mean_hourly_query_data():
    conn = sqlite3.connect('chat_app.db')
    query = """
    SELECT 
        strftime('%H', timestamp) as hour,
        COUNT(*) * 1.0 / (
            SELECT COUNT(DISTINCT DATE(timestamp))
            FROM chats
            WHERE role = 'user'
        ) as mean_query_count
    FROM chats
    WHERE role = 'user'
    GROUP BY hour
    ORDER BY hour
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    
    # Ensure all hours are represented
    all_hours = pd.DataFrame({'hour': [f'{i:02d}' for i in range(24)]})
    df = pd.merge(all_hours, df, on='hour', how='left').fillna(0)
    df['mean_query_count'] = df['mean_query_count'].apply(lambda x: math.ceil(x))
    
    return df

# New function to download database
def get_database_download_link():
    with open('chat_app.db', 'rb') as f:
        bytes = f.read()
    return st.download_button(
        label="Download Database",
        data=bytes,
        file_name="chat_app.db",
        mime="application/octet-stream"
    )

# New function to reinitialize database
def reinitialize_db():
    import os
    if os.path.exists('chat_app.db'):
        os.remove('chat_app.db')
    init_db()
    st.success("Database reinitialized!")
    st.rerun()

# Streamlit app
def main():
    st.title("CPDI Q&A App")
    
    # Display current time in Malaysia timezone
    st.write(f"Current time: {datetime.now(malaysia_tz).strftime('%Y-%m-%d %H:%M:%S')} (GMT+8)")
    
    init_db()

    if 'user' not in st.session_state:
        st.session_state.user = None

    if 'view' not in st.session_state:
        st.session_state.view = 'normal'

    if st.session_state.user is None:
        choice = st.selectbox("Login/Signup", ["Login", "Sign Up"])
        
        if choice == "Login":
            username = st.text_input("Username")
            password = st.text_input("Password", type="password", key="password")
            login_button = st.button("Login")
            
            # Check if Enter key is pressed
            if password and st.session_state.password != password:
                login_button = True
            
            if login_button:
                if not username or not password:
                    st.error("Username and password cannot be empty.")
                else:
                    user = authenticate(username, password)
                    if user:
                        st.session_state.user = user
                        st.success("Logged in successfully")
                        st.rerun()
                    else:
                        st.error("Invalid username or password")
        
        elif choice == "Sign Up":
            new_username = st.text_input("New Username")
            new_password = st.text_input("New Password", type="password")
            
            if st.button("Sign Up"):
                if not new_username or not new_password:
                    st.error("Username and password cannot be empty.")
                elif new_username == 'samson tan':
                    st.error("This username is reserved. Please choose a different username.")
                elif register_user(new_username, new_password):
                    st.success("Account created successfully. Please log in.")
                else:
                    st.error("Username already exists")
    
    else:
        st.write(f"Welcome, {st.session_state.user[1]}!")

        if st.session_state.user[3]:  # Admin user
            st.sidebar.title("Admin Controls")
            view_choice = st.sidebar.radio("Choose View", ['Admin', 'Normal'])
            st.session_state.view = view_choice.lower()

            if st.sidebar.button("Refresh Data"):
                st.rerun()

        if st.session_state.view == 'admin' and st.session_state.user[3]:  # Admin view
            st.subheader("Admin Dashboard")
            
            col1, col2, col3 = st.columns(3)
            with col1:
                if st.button("Clear Cache"):
                    st.cache_data.clear()
                    st.cache_resource.clear()
                    st.rerun()
            with col2:
                get_database_download_link()
            with col3:
                if st.button("Reinitialize Database"):
                    reinitialize_db()
            
            # Display user statistics
            total_users, active_users_24h, total_messages = get_user_stats()
            current_active_users = get_current_active_users()
        
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Users", total_users)
            with col2:
                st.metric("Active Users", active_users_24h)
            with col3:
                st.metric("Current Active Users", current_active_users)
            with col4:
                st.metric("Total Messages", total_messages)
            
            # Display top users
            st.subheader("Top Users")
            top_users_df = get_top_users()
            st.dataframe(top_users_df, hide_index=True)
            
            # Display mean daily query chart
        st.subheader("Mean Daily Queries (All Time)")
        daily_data = get_mean_daily_query_data()
        
        # Create color scale for daily data
        min_val_daily = daily_data['mean_query_count'].min()
        max_val_daily = daily_data['mean_query_count'].max()
        colors_daily = ['#00ff00' if x == min_val_daily else 
                        '#ff0000' if x == max_val_daily else 
                        f'rgb({int(255*((x-min_val_daily)/(max_val_daily-min_val_daily)))},{int(255*((max_val_daily-x)/(max_val_daily-min_val_daily)))},0)' 
                        for x in daily_data['mean_query_count']]

        fig_daily = go.Figure(data=[go.Bar(
            x=daily_data['day_name'],
            y=daily_data['mean_query_count'],
            marker_color=colors_daily,
            text=daily_data['mean_query_count'],
            textposition='auto',
        )])
        
        fig_daily.update_layout(
            title='Mean Queries per Day (All Time)',
            xaxis_title='Day of Week',
            yaxis_title='Mean Number of Queries',
            xaxis = dict(categoryorder='array', categoryarray=['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']),
            yaxis = dict(tickmode = 'linear', tick0 = 0, dtick = 1)
        )
        
        st.plotly_chart(fig_daily)
        
        # Display mean hourly query chart
        st.subheader("Mean Hourly Queries (All Time)")
        hourly_data = get_mean_hourly_query_data()
        
        # Create color scale for hourly data
        min_val_hourly = hourly_data['mean_query_count'].min()
        max_val_hourly = hourly_data['mean_query_count'].max()
        colors_hourly = ['#00ff00' if x == min_val_hourly else 
                         '#ff0000' if x == max_val_hourly else 
                         f'rgb({int(255*((x-min_val_hourly)/(max_val_hourly-min_val_hourly)))},{int(255*((max_val_hourly-x)/(max_val_hourly-min_val_hourly)))},0)' 
                         for x in hourly_data['mean_query_count']]

        fig_hourly = go.Figure(data=[go.Bar(
            x=hourly_data['hour'],
            y=hourly_data['mean_query_count'],
            marker_color=colors_hourly,
            text=hourly_data['mean_query_count'],
            textposition='auto',
        )])
        
        fig_hourly.update_layout(
            title='Mean Queries per Hour (All Time)',
            xaxis_title='Hour of Day',
            yaxis_title='Mean Number of Queries',
            xaxis = dict(tickmode = 'linear', tick0 = 0, dtick = 1),
            yaxis = dict(tickmode = 'linear', tick0 = 0, dtick = 1)
        )
        
        st.plotly_chart(fig_hourly)
        
        # ... (rest of the code remains unchanged)

if __name__ == "__main__":
    main()
