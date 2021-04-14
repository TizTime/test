from flask import Blueprint

admin = Blueprint("admin", __name__)  # 管理员蓝图对象


from .admin import admin