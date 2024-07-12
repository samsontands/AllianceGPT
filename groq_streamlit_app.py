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

# ... [All your existing functions remain unchanged] ...

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

    if st.session_state.user is None:
        choice = st.selectbox("Login/Signup", ["Login", "Sign Up"])
        
        if choice == "Login":
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            if st.button("Login"):
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
        if st.button("Logout"):
            st.session_state.user = None
            st.rerun()

        if st.session_state.user[3]:  # Admin view
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
                st.metric("Active Users (24h)", active_users_24h)
            with col3:
                st.metric("Current Active Users", current_active_users)
            with col4:
                st.metric("Total Messages", total_messages)
            
            # Display top users
            st.subheader("Top Users")
            top_users_df = get_top_users()
            st.dataframe(top_users_df, hide_index=True)
            
            # Display mean hourly query chart
            st.subheader("Mean Hourly Queries (All Time)")
            hourly_data = get_mean_hourly_query_data()
            
            # Create color scale
            min_val = hourly_data['mean_query_count'].min()
            max_val = hourly_data['mean_query_count'].max()
            colors = ['#00ff00' if x == min_val else 
                      '#ff0000' if x == max_val else 
                      f'rgb({int(255*((x-min_val)/(max_val-min_val)))},{int(255*((max_val-x)/(max_val-min_val)))},0)' 
                      for x in hourly_data['mean_query_count']]

            fig = go.Figure(data=[go.Bar(
                x=hourly_data['hour'],
                y=hourly_data['mean_query_count'],
                marker_color=colors,
                text=hourly_data['mean_query_count'].round(2),
                textposition='auto',
            )])
            
            fig.update_layout(
                title='Mean Queries per Hour (All Time)',
                xaxis_title='Hour of Day',
                yaxis_title='Mean Number of Queries',
                xaxis = dict(tickmode = 'linear', tick0 = 0, dtick = 1)
            )
            
            st.plotly_chart(fig)
            
            st.subheader("All Chats")
            all_chats_df = get_all_chats()
            
            # Display chats in the Streamlit app
            st.dataframe(all_chats_df)
            
            # Add a download button
            csv = convert_df_to_csv(all_chats_df)
            st.download_button(
                label="Download chat logs as CSV",
                data=csv,
                file_name="chat_logs.csv",
                mime="text/csv",
            )
        
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

if __name__ == "__main__":
    main()
