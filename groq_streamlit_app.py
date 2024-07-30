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
    
    # Create users table if it doesn't exist
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, is_admin INTEGER)''')
    
    # Add nickname column to users table if it doesn't exist
    c.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in c.fetchall()]
    if 'nickname' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN nickname TEXT")
    
    # Create chats table if it doesn't exist
    c.execute('''CREATE TABLE IF NOT EXISTS chats
                 (id INTEGER PRIMARY KEY, user_id INTEGER, message TEXT, role TEXT, timestamp TEXT)''')
    
    # Create community_messages table if it doesn't exist
    c.execute('''CREATE TABLE IF NOT EXISTS community_messages
                 (id INTEGER PRIMARY KEY, user_id INTEGER, message TEXT, timestamp TEXT)''')
    
    # Check if admin exists, if not, create the fixed admin account
    c.execute("SELECT * FROM users WHERE username=?", ('samson tan',))
    if not c.fetchone():
        hashed_password = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt())
        c.execute("INSERT INTO users (username, password, is_admin, nickname) VALUES (?, ?, ?, ?)",
                  ('samson tan', hashed_password, 1, 'Admin'))
    
    # Create private_messages table
    c.execute('''CREATE TABLE IF NOT EXISTS private_messages
                 (id INTEGER PRIMARY KEY, sender_id INTEGER, receiver_id INTEGER, 
                  message TEXT, timestamp TEXT)''')
    
    conn.commit()
    conn.close()

def set_nickname(user_id, nickname):
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    c.execute("UPDATE users SET nickname = ? WHERE id = ?", (nickname, user_id))
    conn.commit()
    conn.close()

# Add function to get all users for private messaging
def get_all_users_for_messaging():
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    c.execute("SELECT id, COALESCE(nickname, username) as display_name FROM users")
    users = c.fetchall()
    conn.close()
    return users
    
# Add function to save private message
def save_private_message(sender_id, receiver_id, message):
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    timestamp = datetime.now(malaysia_tz).strftime('%Y-%m-%d %H:%M:%S')
    c.execute("INSERT INTO private_messages (sender_id, receiver_id, message, timestamp) VALUES (?, ?, ?, ?)",
              (sender_id, receiver_id, message, timestamp))
    conn.commit()
    conn.close()

# Add function to get private messages
def get_private_messages(user1_id, user2_id):
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    c.execute("""
        SELECT sender_id, message, timestamp
        FROM private_messages
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp ASC
    """, (user1_id, user2_id, user2_id, user1_id))
    messages = c.fetchall()
    conn.close()
    return messages
    
# Update get_nickname function
def get_nickname(user_id):
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    c.execute("SELECT nickname FROM users WHERE id = ?", (user_id,))
    nickname = c.fetchone()[0]
    conn.close()
    return nickname if nickname else "Anonymous"

def save_community_message(user_id, message):
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    timestamp = datetime.now(malaysia_tz).strftime('%Y-%m-%d %H:%M:%S')
    c.execute("INSERT INTO community_messages (user_id, message, timestamp) VALUES (?, ?, ?)",
              (user_id, message, timestamp))
    conn.commit()
    conn.close()

def get_community_messages(limit=100):
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    c.execute("""
        SELECT COALESCE(users.nickname, users.username) as display_name, 
               community_messages.message, 
               community_messages.timestamp 
        FROM community_messages 
        JOIN users ON community_messages.user_id = users.id 
        ORDER BY community_messages.timestamp DESC LIMIT ?
    """, (limit,))
    messages = c.fetchall()
    conn.close()
    return messages

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

# Add this function to delete a user
def delete_user(username):
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    try:
        # First, delete all chats associated with the user
        c.execute("DELETE FROM chats WHERE user_id = (SELECT id FROM users WHERE username = ?)", (username,))
        # Then, delete the user
        c.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        return False
    finally:
        conn.close()

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
        ROUND(COUNT(*) * 1.0 / (
            SELECT COUNT(DISTINCT DATE(timestamp))
            FROM chats
            WHERE role = 'user'
        )) as mean_query_count
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
    df['mean_query_count'] = df['mean_query_count'].astype(int)
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
        ROUND(COUNT(*) * 1.0 / (
            SELECT COUNT(DISTINCT DATE(timestamp))
            FROM chats
        )) as mean_query_count
    FROM chats
    GROUP BY hour
    ORDER BY hour
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    
    # Ensure all hours are represented
    all_hours = pd.DataFrame({'hour': [f'{i:02d}' for i in range(24)]})
    df = pd.merge(all_hours, df, on='hour', how='left').fillna(0)
    df['mean_query_count'] = df['mean_query_count'].astype(int)
    
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

# Add this function to get all users
def get_all_users():
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    c.execute("SELECT username FROM users")
    users = c.fetchall()
    conn.close()
    return users

def main():
    st.title("CPDI Q&A App")
    
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

        if st.session_state.user[3]:
            st.sidebar.title("Admin Controls")
            view_choice = st.sidebar.radio("Choose View", ['Admin', 'Normal'])
            st.session_state.view = view_choice.lower()

            if st.sidebar.button("Refresh Data"):
                st.rerun()

        if st.session_state.view == 'admin' and st.session_state.user[3]:
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
            
            st.subheader("Top Users")
            top_users_df = get_top_users()
            st.dataframe(top_users_df, hide_index=True)
            
            st.subheader("Mean Daily Queries (All Time)")
            daily_data = get_mean_daily_query_data()
            
            daily_min = daily_data['mean_query_count'].min()
            daily_max = daily_data['mean_query_count'].max()
            daily_colors = ['#00ff00' if x == daily_min else 
                            '#ff0000' if x == daily_max else 
                            f'rgb({int(255*((x-daily_min)/(daily_max-daily_min)))},{int(255*((daily_max-x)/(daily_max-daily_min)))},0)' 
                            for x in daily_data['mean_query_count']]

            fig_daily = go.Figure(data=[go.Bar(
                x=daily_data['day_name'],
                y=daily_data['mean_query_count'],
                text=daily_data['mean_query_count'],
                textposition='auto',
                marker_color=daily_colors
            )])
            
            fig_daily.update_layout(
                title='Mean Queries per Day (All Time)',
                xaxis_title='Day of Week',
                yaxis_title='Mean Number of Queries',
                xaxis = dict(categoryorder='array', categoryarray=['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'])
            )
            
            st.plotly_chart(fig_daily)

            st.subheader("Mean Hourly Queries (All Time)")
            hourly_data = get_mean_hourly_query_data()
            
            hourly_min = hourly_data['mean_query_count'].min()
            hourly_max = hourly_data['mean_query_count'].max()
            hourly_colors = ['#00ff00' if x == hourly_min else 
                             '#ff0000' if x == hourly_max else 
                             f'rgb({int(255*((x-hourly_min)/(hourly_max-hourly_min)))},{int(255*((hourly_max-x)/(hourly_max-hourly_min)))},0)' 
                             for x in hourly_data['mean_query_count']]

            fig_hourly = go.Figure(data=[go.Bar(
                x=hourly_data['hour'],
                y=hourly_data['mean_query_count'],
                text=hourly_data['mean_query_count'],
                textposition='auto',
                marker_color=hourly_colors
            )])
            
            fig_hourly.update_layout(
                title='Mean Queries per Hour (All Time)',
                xaxis_title='Hour of Day',
                yaxis_title='Mean Number of Queries',
                xaxis = dict(tickmode = 'linear', tick0 = 0, dtick = 1)
            )
            
            st.subheader("Delete User")
            users_to_delete = [user[0] for user in get_all_users() if user[0] != 'samson tan']
            user_to_delete = st.selectbox("Select user to delete", users_to_delete)
            if st.button("Delete User"):
                if delete_user(user_to_delete):
                    st.success(f"User {user_to_delete} has been deleted.")
                    st.rerun()
                else:
                    st.error("An error occurred while trying to delete the user.")
            
            st.plotly_chart(fig_hourly)
            
            st.subheader("All Chats")
            all_chats_df = get_all_chats()
            
            st.dataframe(all_chats_df)
            
            csv = convert_df_to_csv(all_chats_df)
            st.download_button(
                label="Download chat logs as CSV",
                data=csv,
                file_name="chat_logs.csv",
                mime="text/csv",
            )
        
        else:
            tab1, tab2, tab3, tab4 = st.tabs(["AI Chat", "Community", "Private Chat", "Settings"])

            with tab1:
                st.subheader("Your AI Chat")
                user_chats = get_user_chats(st.session_state.user[0])
                for chat in user_chats:
                    with st.chat_message(chat["role"]):
                        st.markdown(chat["content"])

                user_question = st.chat_input("Ask a question:")
                if user_question:
                    save_chat_message(st.session_state.user[0], user_question, "user")
                    with st.chat_message("user"):
                        st.markdown(user_question)

                    client = init_groq_client()
                    if client:
                        try:
                            with st.chat_message("assistant"):
                                message_placeholder = st.empty()
                                full_response = ""
                                stream = client.chat.completions.create(
                                    messages=[
                                        {"role": "system", "content": "You are a helpful assistant."},
                                        *user_chats,
                                        {"role": "user", "content": user_question}
                                    ],
                                    model="mixtral-8x7b-32768",
                                    max_tokens=1024,
                                    stream=True
                                )
                                for chunk in stream:
                                    if chunk.choices[0].delta.content is not None:
                                        full_response += chunk.choices[0].delta.content
                                        message_placeholder.markdown(full_response + "▌")
                                
                                message_placeholder.markdown(full_response)
                            save_chat_message(st.session_state.user[0], full_response, "assistant")
                        except Exception as e:
                            st.error(f"An error occurred while processing your request: {str(e)}")

            with tab2:
                st.subheader("Community Chat")
                community_messages = get_community_messages()
                
                st.markdown("""
                    <style>
                        .chat-message {
                            padding: 10px;
                            border-radius: 10px;
                            margin-bottom: 10px;
                            max-width: 80%;
                            word-wrap: break-word;
                        }
                        .user-message {
                            background-color: #e6f3ff;
                            float: right;
                        }
                        .other-message {
                            background-color: #f0f0f0;
                            float: left;
                        }
                        .clearfix::after {
                            content: "";
                            clear: both;
                            display: table;
                        }
                    </style>
                """, unsafe_allow_html=True)

                message_container = st.container()
                new_message_placeholder = st.empty()

                with message_container:
                    for nickname, message, timestamp in reversed(community_messages):
                        if nickname == get_nickname(st.session_state.user[0]):
                            st.markdown(f'<div class="chat-message user-message">{message}<br><small>{timestamp}</small></div><div class="clearfix"></div>', unsafe_allow_html=True)
                        else:
                            st.markdown(f'<div class="chat-message other-message"><strong>{nickname}</strong>: {message}<br><small>{timestamp}</small></div><div class="clearfix"></div>', unsafe_allow_html=True)
                
                community_message = st.text_input("Type your message for the community:")
                if st.button("Send to Community"):
                    save_community_message(st.session_state.user[0], community_message)
                    with new_message_placeholder:
                        st.markdown(f'<div class="chat-message user-message">{community_message}<br><small>{datetime.now(malaysia_tz).strftime("%Y-%m-%d %H:%M:%S")}</small></div><div class="clearfix"></div>', unsafe_allow_html=True)
                    st.success("Message sent to the community!")

            with tab3:
                st.subheader("Private Chat")
                users = get_all_users_for_messaging()
                chat_with = st.selectbox("Select user to chat with:", [user[1] for user in users if user[0] != st.session_state.user[0]])
                receiver_id = next(user[0] for user in users if user[1] == chat_with)
                
                private_messages = get_private_messages(st.session_state.user[0], receiver_id)

                private_message_container = st.container()
                new_private_message_placeholder = st.empty()

                with private_message_container:
                    for sender_id, message, timestamp in reversed(private_messages):
                        if sender_id == st.session_state.user[0]:
                            st.markdown(f'<div class="chat-message user-message">{message}<br><small>{timestamp}</small></div><div class="clearfix"></div>', unsafe_allow_html=True)
                        else:
                            st.markdown(f'<div class="chat-message other-message">{message}<br><small>{timestamp}</small></div><div class="clearfix"></div>', unsafe_allow_html=True)
                
                private_message = st.text_input(f"Type your message to {chat_with}:")
                if st.button("Send Private Message"):
                    save_private_message(st.session_state.user[0], receiver_id, private_message)
                    with new_private_message_placeholder:
                        st.markdown(f'<div class="chat-message user-message">{private_message}<br><small>{datetime.now(malaysia_tz).strftime("%Y-%m-%d %H:%M:%S")}</small></div><div class="clearfix"></div>', unsafe_allow_html=True)
                    st.success("Private message sent!")

            with tab4:
                st.subheader("Settings")
                current_nickname = get_nickname(st.session_state.user[0])
                new_nickname = st.text_input("Set your nickname (leave blank for anonymous):", value=current_nickname if current_nickname != "Anonymous" else "")
                if st.button("Update Nickname"):
                    set_nickname(st.session_state.user[0], new_nickname if new_nickname else None)
                    st.success("Nickname updated successfully!")

        if st.button("Logout", key="logout_button"):
            st.session_state.user = None
            st.session_state.view = 'normal'
            st.rerun()

if __name__ == "__main__":
    main()
