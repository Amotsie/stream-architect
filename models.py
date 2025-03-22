from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Boolean
from sqlalchemy.orm import sessionmaker, relationship, declarative_base
import uuid
import bcrypt

mySQL_string = 'mysql+pymysql://root:password@localhost/spha'
sqlite_string = "sqlite+pysqlite:///spha.db"

engine = create_engine(sqlite_string, echo=False)

Session = sessionmaker(bind=engine)
db_session = Session()

Base = declarative_base()

def generate_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"
    userID = Column("userID", String, primary_key=True, default=generate_uuid)
    firstName = Column("firstName", String, nullable=False)
    lastName = Column("lastName", String, nullable=False)
    email = Column("email", String, unique=True, nullable=False)
    password = Column("password", String, nullable=False)

    def __init__(self, firstName, lastName, email, password):
        self.firstName = firstName
        self.lastName = lastName
        self.email = email
        self.password = self.hash_password(password)

    @staticmethod
    def hash_password(password:str)->str:
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')

    def verify_password(self, password:str)->bool:
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

Base.metadata.create_all(engine)

user1 = User("John", "Doe", "johnd@gmail.com", "1234")
db_session.add(user1)
db_session.commit()
