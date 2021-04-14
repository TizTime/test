import functools
from hashlib import md5
from random import Random

from flask import session, jsonify, g


# 定义的验证登录状态的装饰器
def admin_login_required(view_func):
    # wraps函数的作用是将wrapper内层函数的属性设置为被装饰函数view_func的属性
    @functools.wraps(view_func)
    def wrapper(*args, **kwargs):
        # 判断用户的登录状态
        admin_id = session.get("admin_id")

        # 如果用户是登录的，执行视图函数
        if admin_id is not None:
            # 将user_id保存到g对象中，在视图函数中可以通过g对象获取保存数据
            g.admin_id = admin_id
            return view_func(*args, **kwargs)
        else:
            # 如果未登录，返回未登录的信息
            return jsonify(code=400, msg="管理员未登录，请登录")

    return wrapper


def user_login_required(view_func):
    # wraps函数的作用是将wrapper内层函数的属性设置为被装饰函数view_func的属性
    @functools.wraps(view_func)
    def wrapper(*args, **kwargs):
        # 判断用户的登录状态
        user_id = session.get("user_id")

        # 如果用户是登录的，执行视图函数
        if user_id is not None:
            # 将user_id保存到g对象中，在视图函数中可以通过g对象获取保存数据
            g.user_id = user_id
            return view_func(*args, **kwargs)
        else:
            # 如果未登录，返回未登录的信息
            return jsonify(code=400, msg="用户未登录，请登录")

    return wrapper


# # 管理员显示所有用户信息(可能会用到吧)
# def show_all_user_info(view_func):
#     @functools.wraps(view_func)
#     def wrapper(*args, **kwargs):
#         user_info = []
#         user_s = Users.query.all()
#         for user in user_s:
#             data = {
#                 "用户id": user.id,
#                 "用户昵称": user.username,
#                 "用户密码": user.password,
#                 "用户手机号": user.phone,
#                 "用户地址": user.address,
#                 "用户创建账户时间": user.create_time.strftime("%Y-%m-%d %H:%M:%S"),
#                 "用最近一次登录时间": user.update_time.strftime("%Y-%m-%d %H:%M:%S")
#             }
#             user_info.append(data)
#
#         resp_dict = dict(all_user_data=user_info, msg="显示所有用户信息", code=200)
#         resp_json = jsonify(resp_dict)
#         return resp_json
#

# 随机生成4位大小写字母、数字组成的salt值
def create_salt(length = 4):
    salt = ""
    chars = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQq" \
            "RrSsTtUuVvWwXxYyZz0123456789"
    len_chars = len(chars) - 1
    random = Random()
    for i in range(length):
        # 每次从char 中随机取一位
        salt += chars[random.randint(0, len_chars)]
    return salt


# 获取原始密码+salt的md5值
def create_md5(pwd, salt):
    md5_obj = md5()
    md5_obj.update((pwd + salt).encode("utf8"))
    return md5_obj.hexdigest()


