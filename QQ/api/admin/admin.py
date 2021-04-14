from flask import request, jsonify, session, g
from api.utils.tool import admin_login_required, create_salt, create_md5
from api import Admin, User, db
from . import admin
import re


# 成功响应
@admin.route("/", methods=["GET"])
def hello_world():
    return "亲爱的管理员立秋~你好！"


# 管理员注册
@admin.route("/register", methods=["POST"])
def admin_register():
    """

    测试账号 username:toto
    测试账号 password:tototo
{
    "username": "toto",
    "password": "tototo",
    "admin_phone": "8613729666666",
    "admin_email": "wuwu@outlook.com"
}
    :rtype: object
    """
    try:
        # 获得账户密码并注册到数据库
        my_json = request.get_json()
        print(my_json)
        username = my_json.get("username")
        password = my_json.get("password")
        admin_phone = my_json.get("admin_phone")
        admin_email = my_json.get("admin_email")

        # 生成盐和进行hash加密并将盐和hash值保存到数据库中
        salt = create_salt()
        md5 = create_md5(password, salt)

        # 检测账号,手机号,邮箱是否在数据库中存在，如果已存在，禁止注册。
        admin_repeat_username = Admin.select().where(Admin.username == username).first()
        if admin_repeat_username is not None:
            return jsonify(msg="账号已存在，请重新注册", code=4000)
        admin_repeat_phone = Admin.select().where(Admin.phone == admin_phone).first()
        if admin_repeat_phone is not None:
            return jsonify(msg="手机号已被使用，请重新注册", code=4000)
        admin_repeat_email = Admin.select().where(Admin.email == admin_email).first()
        if admin_repeat_email is not None:
            return jsonify(msg="邮箱已被使用，请重新注册", code=4000)

        # 发现获得参数不完整，返回错误代码4000
        if not all([username, password, admin_phone, admin_email]):
            return jsonify(msg="参数不完整。", code=4000)

        # 验证输入合法性
        phone_standard = r"^(0|86|17951)?(13[0-9]|15[012356789]" \
                         r"|17[013678]|18[0-9]|14[57])[0-9]{8}$"
        emil_standard = r"^([a-zA-Z0-9]+[_|\_|\.]?)*[a-zA-Z0-9]+@([a-zA-Z0-9]" \
                        r"+[_|\_|\.]?)*[a-zA-Z0-9]+\.[a-zA-Z]{2,3}$"
        phone_test = re.compile(phone_standard)
        emil_test = re.compile(emil_standard)

        flag = False
        if admin_phone == phone_test.match(admin_phone).group(0) \
                and admin_email == emil_test.match(admin_email).group(0):
            flag = True

        if not flag:
            return jsonify(msg="手机号或邮箱不符合格式，请重新输入!", code=4000)

        # 添加到数据库
        table_admin = Admin(username=username, password=password, phone=admin_phone,
                            email=admin_email, salt=salt, password_md5=md5)
        try:
            table_admin.save()
            return jsonify(code=200, msg="注册成功。", username=username)  # 提示注册成功
        except Exception as e:
            print(e)
            table_admin.rollback()
            return jsonify(msg="数据库创建出错", code=4001)

    except Exception as e:
        print(e)
        return jsonify(msg="访问错误，请检查是否正确访问。", code=4002)


# 管理员登录
@admin.route("/login", methods=["POST"])
def admin_login():
    """
    测试账号 username:toto
    测试账号 password:tototo
{
    "username": "toto",
    "password": "tototo"
}
    :rtype: object
    """
    get_data = request.get_json()
    username = get_data.get("username")
    password = get_data.get("password")

    if not all([username, password]):
        return jsonify(msg="参数完整，请重新输入。", code=4000)

    # TODO 通过id配对数据库，输入密码加盐hash加密与数据库里的password_md5对比。
    input_admin = Admin.select().where(Admin.username == username).first()
    if input_admin is not None:
        # 取出salt并给输入密码+salt
        salt = input_admin.salt
        md5 = create_md5(password, salt)
        if input_admin.password_md5 == md5:
            # 如果验证通过 将登录状态保存到session中
            session["admin_username"] = username
            session["admin_id"] = input_admin.id
            return jsonify(msg="登录成功。", code=200, username=username)
        else:
            return jsonify(msg="密码错误，请重新输入", code=4000)
    else:
        return jsonify(msg="账号不存在，请注册账户或重新输入。", code=4000)


# 检测管理员登录状态
@admin.route("/session", methods=["GET"])
def admin_check_session():
    # 检测session中的username
    username = session.get("admin_username")
    if username is not None:
        return jsonify(username=username, code=200)
    else:
        return jsonify(msg="未登录，请你登录。", code=4000)


# 管理员登出
@admin.route("/logout", methods=["DELETE"])
@admin_login_required
def admin_logout():
    # 清除session保存的信息
    session.clear()
    return jsonify(msg="成功退出管理账户！", code=200)


# 管理员修改密码
@admin.route("/password", methods=["POST"])
@admin_login_required
def change_admin_password():
    """
{
    "old_password": "tototo",
    "new_password": "toto"
}
    :rtype: object
    """
    admin_id = g.admin_id
    my_json = request.get_json()
    old_password = my_json.get("old_password")
    new_password = my_json.get("new_password")

    if not all([new_password, old_password, admin_id]):
        return jsonify(code=4000, msg="参数不完整，请重新输入。")

    # 从g中获得uid并在admin中查找，查找到修改密码并提交
    admin = Admin.select().where(Admin.id == admin_id).first()
    if admin.password != old_password:
        return jsonify(code=4000, msg="输入密码错误，请重试！")
    admin.password = new_password

    try:
        admin.save()
    except Exception as e:
        print(e)
        admin.rollback()
        return jsonify(code=4000, msg="修改密码失败，请重试！")

    return jsonify(code=200, msg="修改密码成功！")


# 显示所有用户信息
@admin.route("/user/show", methods=["GET"])
@admin_login_required
def show_all_user_info():
    user_info = []
    user_s = User.select().order_by(User.id.asc())
    # 遍历所有数据并放入字典中
    for user in user_s:
        data = {
            "用户id": user.id,
            "用户昵称": user.username,
            "用户密码": user.password,
            "用户手机号": user.phone,
            "用户地址": user.email,
            "用户创建账户时间": user.create_time
        }
        user_info.append(data)

    resp_dict = dict(all_user_data=user_info, msg="显示所有用户信息", code=200)
    resp_json = jsonify(resp_dict)
    return resp_json


# 删除用户信息
@admin.route("/user/delete", methods=["POST"])
@admin_login_required
def delete_user_data():
    """
{
    "user_id": 1
}
    :rtype: object
    """
    my_json = request.get_json()
    print(my_json)
    # 获取输入的id并进行删除操作
    user_id = my_json.get("user_id")

    if user_id:
        user_info = User.select().where(User.id == user_id).first()

        if user_info is None:
            return jsonify(msg="该用户不存在，请重弄新输入", code=4000)

        try:
            # 删除该用户
            user_info.delete_instance()
            return jsonify(code=200, msg="删除用户信息成功", user_id=user_info.id, username=user_info.username)
        except Exception as e:
            print(e)
            user_info.rollback()
            return jsonify(msg="删除用户信息失败", code=4003)
    else:
        return jsonify(msg="参数输入不完整，请重新输入。", code=4000)


# 修改用户密码
@admin.route("/user/change", methods=["POST"])
@admin_login_required
def change_user_password():
    """
    输入需要修改的用户信息对应的id和新的密码
{
    "user_id": 1,
    "new_password": "gogo"
}
    :rtype: object
    """
    my_json = request.get_json()
    print(my_json)
    # 获取输入的id和想要修改的密码
    user_id = my_json.get("user_id")
    new_password = my_json.get("new_password")
    if user_id:
        user_info = User.select().where(User.id == user_id).first()

        if user_info is None:
            return jsonify(msg="该用户不存在，请重新输入", code=4000)

        # 对该用户的密码进行修改
        user_info.password = new_password

        try:
            user_info.save()
            return jsonify(msg="用户密码修改成功", user_id=user_info.id, password=new_password, code=200)
        except Exception as e:
            print(e)
            db.session.rollback()
            return jsonify(msg="修改用户密码失败", code=4003)

    else:
        return jsonify(msg="参数输入不完整，请重新输入。", code=4000)
