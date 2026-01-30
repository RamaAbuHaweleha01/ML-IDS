import requests

TOKEN = "Write_Token"
URL = f"https://api.telegram.org/bot{TOKEN}/getUpdates"

response = requests.get(URL).json()

if "result" in response and len(response["result"]) > 0:
    for update in response["result"]:
        chat = update["message"]["chat"]
        print("Chat ID:", chat["id"])
        print("Username:", chat.get("username"))
        print("First Name:", chat.get("first_name"))
        print("-" * 30)
else:
    print("❌ No messages yet. Send a message to the bot first.")
