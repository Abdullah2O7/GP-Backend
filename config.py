import os
from dotenv import load_dotenv

load_dotenv()
class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')
    MONGO_URI = 'mongodb+srv://abdullahmohamed1047:HuexVTFWCHGP8wXU@cluster0.ydoaic1.mongodb.net/'
    SENDER_EMAIL = os.getenv('SENDER_EMAIL')
    SENDER_PASSWORD = os.getenv('SENDER_PASSWORD')
