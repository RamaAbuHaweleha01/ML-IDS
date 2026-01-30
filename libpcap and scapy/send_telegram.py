import requests

BOT_TOKEN = "8382806780:AAEQX65plGY7H04rR0Ssdw6dOIKgt2dCshc"
CHAT_ID = "7589392051"
MESSAGE = "✅ Test message from Ubuntu"

url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

payload = {
    "chat_id": CHAT_ID,
    "text": MESSAGE
}

response = requests.post(url, data=payload)

if response.status_code == 200:
    print("✅ Message sent successfully!")
else:
    print("❌ Failed to send message")
    print(response.text)
