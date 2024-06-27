import streamlit as st
from groq import Groq
from github import Github
import base64
import json
from datetime import datetime

# Function to initialize Groq client
def init_groq_client():
    try:
        api_key = st.secrets["GROQ_API_KEY"]
        return Groq(api_key=api_key)
    except Exception as e:
        st.error(f"Error initializing Groq client: {str(e)}")
        return None

# Function to log chat to GitHub
def log_chat_to_github(messages):
    try:
        g = Github(st.secrets["GITHUB_TOKEN"])
        repo = g.get_repo(st.secrets["GITHUB_REPO"])
        file_path = f"chat_logs/chat_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        content = json.dumps(messages, indent=2)
        repo.create_file(file_path, f"Log chat {datetime.now()}", content)
        
        st.success("Chat log saved to GitHub")
    except Exception as e:
        st.error(f"Error logging chat to GitHub: {str(e)}")

# Streamlit app
st.title("Groq AI Q&A App with GitHub Logging")

# Initialize session state for conversation history
if "messages" not in st.session_state:
    st.session_state.messages = []

# Display conversation history
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Main app
user_question = st.chat_input("Ask a question:")

if user_question:
    # Add user message to chat history
    st.session_state.messages.append({"role": "user", "content": user_question})
    with st.chat_message("user"):
        st.markdown(user_question)

    # Initialize Groq client
    client = init_groq_client()
    if client:
        try:
            with st.chat_message("assistant"):
                message_placeholder = st.empty()
                full_response = ""

                # Create a chat completion
                stream = client.chat.completions.create(
                    messages=[
                        {"role": "system", "content": "You are a helpful assistant."},
                        *st.session_state.messages
                    ],
                    model="mixtral-8x7b-32768",
                    max_tokens=1024,
                    stream=True
                )

                # Stream the response
                for chunk in stream:
                    if chunk.choices[0].delta.content is not None:
                        full_response += chunk.choices[0].delta.content
                        message_placeholder.markdown(full_response + "▌")
                
                message_placeholder.markdown(full_response)

            # Add assistant response to chat history
            st.session_state.messages.append({"role": "assistant", "content": full_response})

            # Log chat to GitHub
            log_chat_to_github(st.session_state.messages)

        except Exception as e:
            st.error(f"An error occurred while processing your request: {str(e)}")

# Add a button to manually trigger logging
if st.button("Save Chat Log to GitHub"):
    log_chat_to_github(st.session_state.messages)
