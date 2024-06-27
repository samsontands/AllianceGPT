import streamlit as st
from groq import Groq

# Remove the sidebar API key input
# Instead, use st.secrets to get the API key
api_key = st.secrets["GROQ_API_KEY"]

# Initialize Groq client
client = Groq(api_key=api_key)

# Streamlit app
st.title("Groq AI Q&A App")

# Sidebar for API key input
api_key = st.sidebar.text_input("Enter your Groq API key", type="password")
if api_key:
    os.environ["GROQ_API_KEY"] = api_key

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
    if not api_key:
        st.error("Please enter your Groq API key in the sidebar.")
    else:
        # Add user message to chat history
        st.session_state.messages.append({"role": "user", "content": user_question})
        with st.chat_message("user"):
            st.markdown(user_question)

        # Initialize Groq client
        client = init_groq_client(api_key)
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

            except Exception as e:
                st.error(f"An error occurred while processing your request: {str(e)}")
