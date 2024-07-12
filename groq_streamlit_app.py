import streamlit as st
import sqlite3
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime
import pytz

# Set the time zone to GMT+8 (Malaysia)
malaysia_tz = pytz.timezone('Asia/Kuala_Lumpur')

# Get all chats from the database
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
    df['timestamp'] = df['timestamp'].dt.tz_localize('UTC').dt.tz_convert(malaysia_tz)
    df['timestamp'] = df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
    
    return df

# Convert DataFrame to CSV
def convert_df_to_csv(df):
    return df.to_csv(index=False).encode('utf-8')

# Function to get mean hourly query data
def get_mean_hourly_query_data(df):
    df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
    hourly_counts = df['hour'].value_counts().sort_index()
    total_days = (pd.to_datetime(df['timestamp']).max() - pd.to_datetime(df['timestamp']).min()).days + 1 or 1
    mean_queries = hourly_counts / total_days
    result_df = pd.DataFrame({'hour': mean_queries.index, 'mean_query_count': mean_queries.values})
    all_hours = pd.DataFrame({'hour': range(24)})
    result_df = pd.merge(all_hours, result_df, on='hour', how='left').fillna(0)
    result_df['hour'] = result_df['hour'].astype(str).str.zfill(2)
    return result_df.sort_values('hour')

# Streamlit app
def main():
    st.title("CPDI Q&A App - Data Download")
    
    # Display current time in Malaysia timezone
    st.write(f"Current time: {datetime.now(malaysia_tz).strftime('%Y-%m-%d %H:%M:%S')} (GMT+8)")
    
    try:
        # Get all chats from the database
        all_chats_df = get_all_chats()
        
        # Display mean hourly query chart
        st.subheader("Mean Hourly Queries")
        hourly_data = get_mean_hourly_query_data(all_chats_df)
        
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
            title='Mean Queries per Hour',
            xaxis_title='Hour of Day',
            yaxis_title='Mean Number of Queries',
            xaxis = dict(tickmode = 'linear', tick0 = 0, dtick = 1)
        )
        
        st.plotly_chart(fig)
        
        st.subheader("All Chats")
        
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
    
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")
        st.error("If the database doesn't exist or is empty, you may need to initialize it or add data first.")

if __name__ == "__main__":
    main()
