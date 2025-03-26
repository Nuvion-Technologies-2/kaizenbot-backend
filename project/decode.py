# import base64

# token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc0MDUxMTU3OCwianRpIjoiZWI2NmM5ODItZWI3NS00MzMyLWI5ZGYtMTdmMWFmMzE2ZjlmIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6Im1hbmFnZXJAZXhhbXBsZS5jb20iLCJuYmYiOjE3NDA1MTE1NzgsImNzcmYiOiJhNGY1OTNjYS0wOWQ3LTRhZWMtODdjYy05YTExNmFiMzFhMjkiLCJleHAiOjE3NDMxMDM1NzgsInJvbGUiOiJtYW5hZ2VyIn0.XAa-YBSwLnx9FCYaIsvPX6uFK1SQBJA0BSglYFlFGyc"

# # token = "gAAAAABnvWpZBnoYnidTJIVDLpVP5Yplic7wDTQs2RJolXO2pD52cDWQjcbN5mJiQROz7Y5Yd4UkYh5xm_HTf3hSFukcJ5Q_41p7XQHpi8tOXPgcfJZ2vxuDYE6zftC7tIwkhsueS3SvRQ_mfV_1ZAtOP1ySachQyiOLarbPANB4wRYIHpc0LMOsfXfKlBlc1btSmmGWEvBka3AQCIUEm6rNiI6a6JylB9IuYEC8Bf-dk7y6uXDYPWGR7QYAFune3Si8aE_xt7TKXQjz_9JsHiFfTttilK0oKetK6De7-vfnavzkpQwHkochp8EO0enw5b5lDO9zKtd4KMwLOwii_6Ojuycnu2HEJvyHVrT8BS_s9j_TrhVBzHQnuI-6iWGaXUtZcaaCkPIhH_r7yJ7ShM96gkcojeCEcP2CRwTs1-qfUMpMjaag4LsMDVSu3LP6N15RAa1-OuGgVRMmFRhGeHjSRr8BTjQsuCy6Ks4kQIkJpk_UAggtJ81StXtodEcgGbIgGuW59YrySVh0K0KesVciHxN21LxrcbNdmkwuOT7nNHL5RyNqPRha-077VwJJvlhN7XZ46G_1v7J5WMGIBeZG657PmeZ8VQ=="

# try:
#     header, payload, signature = token.split(".")
#     print("Header:", base64.urlsafe_b64decode(header + "==").decode("utf-8"))
#     print("Payload:", base64.urlsafe_b64decode(payload + "==").decode("utf-8"))
# except ValueError:
#     print("❌ Invalid Token: Not enough segments")

from flask_jwt_extended import JWTManager, decode_token
from flask import Flask
from flask_jwt_extended import decode_token
from config import Config

# ✅ Create a minimal Flask app to provide context
app = Flask(__name__)
app.config.from_object(Config)
jwt = JWTManager(app)

jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc0MDU2MTYxNiwianRpIjoiNTQzNjFjZWUtYzQyZS00MWIxLTgzYzktNjM5MzM2MTJhYjZkIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6Im1hbmFnZXJAZXhhbXBsZS5jb20iLCJuYmYiOjE3NDA1NjE2MTYsImNzcmYiOiIyOWMxOWIxMS0yMDE4LTQ1OWQtYjAxZS04MzJmYTc5ODFlZmUiLCJyb2xlIjoibWFuYWdlciJ9.FpbwtdFP8GLvvWf3PCF6YRDI62ZzOqBwDWAq_QY9BzU"

with app.app_context():
    decoded = decode_token(jwt_token)
    print(decoded)



