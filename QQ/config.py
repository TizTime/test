# 需要的配置
import redis


"""
这是生产环境的配置
注释部分是sqlalchemy数据库的配置，
其它正在使用的是session的生产环境。
"""


class Config:
    # SQLALCHEMY_TRACK_MODIFICATIONS = False
    # flask-session配置
    SESSION_TYPE = "redis"
    SESSION_USE_SIGNER = True  # 对cookie中session_id进行隐藏处理 加密混淆
    PERMANENT_SESSION_LIFETIME = 600  # session数据的有效期，单位秒
    SECRET_KEY = "rhbcwk3LcX4zzJ7QixLq+w=="  # openssl 随机生成密码


# 开发环境
class DevelopmentConfig(Config):
    """开发模式的配置信息"""
    # SQLALCHEMY_DATABASE_URI = "mysql+pymysql://root:@127.0.0.1:3306/ap_flask"  # 本地数据库
    # SESSION_REDIS = redis.Redis(host='127.0.0.1', port=6379, password="jamkung", db=2)  # 操作的redis配置
    # 使用本地redis端口 redis_cli; select 2; key*;
    SESSION_REDIS = redis.Redis(host='127.0.0.1', port=6379, db=2)  # 操作的redis配置
    DEBUG = True


# 线上环境
class ProductionConfig(Config):
    """生产环境配置信息"""
    # SQLALCHEMY_DATABASE_URI = "mysql+pymysql://root:@127.0.0.1:3306/ap_flask_pro"
    SESSION_REDIS = redis.Redis(host='pukgai.com', port=6379, password="jamkung", db=3)  # 操作的redis配置


config_map = {
    "develop": DevelopmentConfig,
    "product": ProductionConfig
}
