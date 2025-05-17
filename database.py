from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# SQLite 数据库 URL
DATABASE_URL = "sqlite:///./pve_nat.db"

# 创建 SQLAlchemy 引擎
engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False} # SQLite 需要这个参数，非线程安全
)

# 创建会话本地生成器
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 基础模型，用于声明表
Base = declarative_base()

# 可以在这里定义你的数据库模型，例如 NAT 规则模型
# from sqlalchemy import Column, Integer, String, Boolean, ForeignKey
# class NatRule(Base):
#     __tablename__ = "nat_rules"
#     id = Column(Integer, primary_key=True, index=True)
#     container_id = Column(Integer, index=True)
#     container_internal_ip = Column(String)
#     container_internal_port = Column(Integer)
#     pve_host_ip = Column(String)
#     pve_external_port = Column(Integer)
#     protocol = Column(String) # tcp, udp, both
#     enabled = Column(Boolean, default=True)
#     description = Column(String, nullable=True)

# 调用 create_all 创建表 (如果不存在)
# Base.metadata.create_all(bind=engine)

# 依赖函数，用于获取数据库 session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
