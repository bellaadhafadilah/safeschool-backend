import os

class Config:
    # URL MongoDB Atlas yang bisa dimodifikasi
    MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://bellaadha:bellaadha125_@cluster0.mongodb.net/safeschool?retryWrites=true&w=majority")
    SECRET_KEY = os.getenv("SECRET_KEY", "safeschool123")
