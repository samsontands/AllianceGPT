import streamlit as st
import sqlite3
import pandas as pd

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
    
    # Convert all columns to string
    for col in df.columns:
        df[col] = df[col].astype(str)
    
    return df

# Convert DataFrame to CSV
def convert_df_to_csv(df):
    return df.to_csv(index=False).encode('utf-8')

# Streamlit app
def main():
    st.title("CPDI Q&A App - Data Download")
    
    try:
        # Get all chats from the database
        all_chats_df = get_all_chats()
        
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
    
