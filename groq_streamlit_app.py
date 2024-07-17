import streamlit as st
import sqlite3
from groq import Groq
import bcrypt
from datetime import datetime, timedelta
import pandas as pd
import pytz
import plotly.graph_objects as go

# ... (previous code remains unchanged until the get_user_chats function)

# Get user's chat history (reversed order)
def get_user_chats(user_id):
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    c.execute("SELECT message, role FROM chats WHERE user_id=? ORDER BY timestamp DESC", (user_id,))
    chats = c.fetchall()
    conn.close()
    return [{"role": role, "content": message} for message, role in chats]

# ... (previous code remains unchanged until the get_mean_hourly_query_data function)

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

# ... (previous code remains unchanged until the main function)

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
        # ... (login and signup code remains unchanged)
    
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
            
            # ... (admin dashboard code remains unchanged)
            
            # Display mean daily query chart
            st.subheader("Mean Daily Queries (All Time)")
            daily_data = get_mean_daily_query_data()
            
            # Create color scale
            min_val = daily_data['mean_query_count'].min()
            max_val = daily_data['mean_query_count'].max()
            colors = ['#00ff00' if x == min_val else 
                      '#ff0000' if x == max_val else 
                      f'rgb({int(255*((x-min_val)/(max_val-min_val)))},{int(255*((max_val-x)/(max_val-min_val)))},0)' 
                      for x in daily_data['mean_query_count']]

            fig = go.Figure(data=[go.Bar(
                x=daily_data['day_name'],
                y=daily_data['mean_query_count'],
                marker_color=colors,
                text=daily_data['mean_query_count'].round(2),
                textposition='auto',
            )])
            
            fig.update_layout(
                title='Mean Queries per Day (All Time)',
                xaxis_title='Day of Week',
                yaxis_title='Mean Number of Queries',
                xaxis = dict(categoryorder='array', categoryarray=['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'])
            )
            
            st.plotly_chart(fig)
            
            # ... (rest of the admin view code remains unchanged)
        
        else:  # Regular user view
            st.subheader("Your Chat")
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
                                    *reversed(user_chats),  # Reverse the chat history for the AI
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

        # Logout button at the bottom
        if st.button("Logout", key="logout_button"):
            st.session_state.user = None
            st.session_state.view = 'normal'
            st.rerun()

if __name__ == "__main__":
    main()
