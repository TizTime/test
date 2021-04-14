from flask import request, jsonify, session, g
from api.utils.tool import user_login_required, create_md5, create_salt
from api import User
from . import user
import re


# 成功响应
@user.route("/", methods=["GET"])
def hello_world():
    return "亲爱的用户立秋~你好！"


# 用户注册
@user.route("/register", methods=["POST"])
def user_register():
    """
{
    "username": "gogo",
    "password": "gogogo",
    "user_phone": "8613729666666",
    "user_email": "wuwu@outlook.com"
}
    :rtype: object
    """
    try:
        # 获得账户密码手机号邮箱并注册到数据库
        my_json = request.get_json()
        print(my_json)
        username = my_json.get("username")
        password = my_json.get("password")
        user_phone = my_json.get("user_phone")
        user_email = my_json.get("user_email")

        # 生成盐和进行hash加密并将盐和hash值保存到数据库中
        salt = create_salt()
        md5 = create_md5(password, salt)

        # 检测账号,手机号,邮箱是否在数据库中存在，如果已存在，禁止注册。
        user_repeat_username = User.select().where(User.username == username).first()
        if user_repeat_username is not None:
            return jsonify(msg="账号已存在，请重新注册", code=4001)
        user_repeat_phone = User.select().where(User.phone == user_phone).first()
        if user_repeat_phone is not None:
            return jsonify(msg="手机号已被使用，请重新注册", code=4001)
        user_repeat_email = User.select().where(User.email == user_email).first()
        if user_repeat_email is not None:
            return jsonify(msg="邮箱已被使用，请重新注册", code=4001)

        # 发现获得参数不完整，返回错误代码4000
        if not all([username, password, user_phone, user_email]):
            return jsonify(msg="注册失败！参数不完整。", code=4001)

        # 验证输入合法性
        phone_standard = r"^(0|86|17951)?(13[0-9]|15[012356789]" \
                         r"|17[013678]|18[0-9]|14[57])[0-9]{8}$"
        emil_standard = r"^([a-zA-Z0-9]+[_|\_|\.]?)*[a-zA-Z0-9]+@([a-zA-Z0-9]" \
                        r"+[_|\_|\.]?)*[a-zA-Z0-9]+\.[a-zA-Z]{2,3}$"
        phone_test = re.compile(phone_standard)
        emil_test = re.compile(emil_standard)

        flag = False
        if user_phone == phone_test.match(user_phone).group(0) \
                and user_email == emil_test.match(user_email).group(0):
            flag = True
        if not flag:
            return jsonify(msg="手机号或邮箱不符合格式，请重新输入!", code=4000)

        # 添加到数据库
        table_user = User(username=username, password=password, phone=user_phone,
                          email=user_email, salt=salt, password_md5=md5)
        try:
            table_user.save()
            return jsonify(code=200, msg="注册成功。", username=username)  # 提示注册成功
        except Exception as e:
            print(e)
            table_user.rollback()
            return jsonify(msg="访问数据库出错", code=4001)

    except Exception as e:
        print(e)
        return jsonify(msg="访问错误，请检查是否正确访问。", code=4002)


# 用户登录
@user.route("/login", methods=["POST"])
def user_login():
    """
    测试账号 username:gogo
    测试账号 password:gogogo
{
    "username": "gogo",
    "password": "gogogo"
}
    :rtype: object
    """
    get_data = request.get_json()
    username = get_data.get("username")
    password = get_data.get("password")

    if not all([username, password]):
        return jsonify(msg="参数输入不完整，请重新输入。", code=4000)

    # TODO 通过id配对数据库，输入密码加盐hash加密与数据库里的password_md5对比。
    input_user = User.select().where(User.username == username).first()
    # 如果用户密码存在并且密码正确
    if input_user is not None:
        # 取出salt并给输入密码+salt
        salt = input_user.salt
        md5 = create_md5(password, salt)
        if input_user.password_md5 == md5:
            # 如果验证通过 将登录状态保存到session中
            session["user_username"] = username
            session["user_id"] = input_user.id
            return jsonify(msg="登录成功。", code=200, username=username)
        else:
            return jsonify(msg="密码错误，请重新输入", code=4000)
    else:
        return jsonify(msg="账号不存在，请注册账户或重新输入。", code=4000)


# 检测用户登录状态
@user.route("/session", methods=["GET"])
def user_check_session():
    # 检测session中的username
    username = session.get("user_username")
    if username is not None:
        return jsonify(username=username, code=200)
    else:
        return jsonify(msg="未登录，请你登录。", code=4000)


# 用户登出
@user.route("/logout", methods=["DELETE"])
@user_login_required
def user_logout():
    session.clear()
    return jsonify(msg="成功退出登录！", code=200)


# 显示所有个人信息
@user.route("/show_info", methods=["GET"])
@user_login_required
def show_info():
    user_id = g.user_id
    user_info = User.select().where(User.id == user_id).first()
    data = {
        "你的id": user_info.id,
        "你的昵称": user_info.username,
        "你的手机号": user_info.phone,
        "你的地址": user_info.email,
        "你创建账户时间": user_info.create_time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    # 将数据转化为json字符串
    resp_dict = dict(code=200, msg="个人信息展示", user_data=data)
    resp_json = jsonify(resp_dict)
    return resp_json


# 用户修改密码
@user.route("/password", methods=["POST"])
@user_login_required
def change_admin_password():
    """
{
    "old_password": "gogogo",
    "new_password": "gogo"
}
    :rtype: object
    """
    user_id = g.user_id
    my_json = request.get_json()
    old_password = my_json.get("old_password")
    new_password = my_json.get("new_password")

    if not all([new_password, old_password, user_id]):
        return jsonify(code=4000, msg="参数不完整，请重新输入。")

    # 从g中获得uid并在admin中查找，查找到修改密码并提交
    user = User.select().where(User.id == user_id).first()
    if user.password != old_password:
        return jsonify(code=4000, msg="输入密码错误，请重试！")
    user.password = new_password

    try:
        user.save()
    except Exception as e:
        print(e)
        user.rollback()
        return jsonify(code=4000, msg="修改密码失败，请重试！")

    return jsonify(code=200, msg="修改密码成功！")
