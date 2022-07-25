from django.shortcuts import render
import os
import socketio
import environ


# Create your views here.

env = environ.Env()
environ.Env.read_env(".env")

mgr = socketio.AsyncRedisManager(os.environ.get("REDIS_URL"))
sio = socketio.AsyncServer(
    async_mode="asgi", client_manager=mgr, cors_allowed_origins="*"
)