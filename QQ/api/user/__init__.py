from flask import Blueprint

user = Blueprint("user", __name__)  # 用户蓝图对象

from .user import user
