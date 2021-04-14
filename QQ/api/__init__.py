from flask import Flask
from flask_session import Session
from config import config_map
import datetime
from peewee import CharField, Model, DateTimeField, MySQLDatabase


def create_app(dev_namw):
    """
    :param dev_namw:  选择环境参数
    :return:
    :rtype: object
    """
    app = Flask(__name__)
    config_class = config_map.get(dev_namw)
    app.config.from_object(config_class)  # 从类中读取需要的信息

    # 利用flask_session，将session数据保存到redis中
    Session(app)

    # 注册蓝图
    from api import admin, user

    app.register_blueprint(user.user, url_prefix="/user")
    app.register_blueprint(admin.admin, url_prefix="/admin")
    return app


db = MySQLDatabase("sql_peewee", host="127.0.0.1", port=3306, user="root", passwd="")
db.connection()


class BaseModel(Model):

    class Meta:
        database = db


# 用户数据表
class User(BaseModel):
    username = CharField(verbose_name="用户名", unique=True, max_length=24, null=False)
    password = CharField(verbose_name="密码", max_length=24, null=False)
    salt = CharField(verbose_name="保存加密用的salt值")
    password_md5 = CharField(verbose_name="保存加密后的md5值")
    phone = CharField(verbose_name="手机号", unique=True, max_length=13, null=False)
    email = CharField(verbose_name="邮箱", unique=True, max_length=64, null=False)
    create_time = DateTimeField(default=datetime.datetime.now)

    class Meta:
        table_name = "user"


# 管理员数据表
class Admin(BaseModel):
    username = CharField(verbose_name="管理员名字", unique=True, max_length=24, null=False)
    password = CharField(verbose_name="密码", max_length=24, null=False)
    salt = CharField(verbose_name="保存加密用的salt值")
    password_md5 = CharField(verbose_name="保存加密后的md5值")
    phone = CharField(verbose_name="手机号", unique=True, max_length=13, null=False)
    email = CharField(verbose_name="邮箱", unique=True, max_length=64, null=False)
    create_time = DateTimeField(default=datetime.datetime.now)

    class Meta:
        table_name = "admin"


try:
    User.create_table()  # 创建user表
    Admin.create_table()  # 创建admin表
except Exception as e:
    print(e)
