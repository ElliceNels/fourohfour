from sqlalchemy import CheckConstraint, Column, Integer, String, BLOB, ForeignKey, DateTime, DECIMAL
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()

class Users(Base):
    """User table to store user information."""
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False)
    password = Column(String(100), nullable=False)
    salt = Column(BLOB, nullable=False)
    public_key = Column(BLOB, nullable=False, unique=True)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)

    files = relationship(
        "Files",
        back_populates="user",
        cascade="all, delete-orphan"
    )
    file_permissions = relationship(
        "FilePermissions",
        back_populates="user",
        cascade="all, delete-orphan"
    )
    # Cascades: When a user is deleted, all their files and permissions are also deleted !!

class FilePermissions(Base):
    """File permissions table to store user-specific file access permissions."""
    __tablename__ = 'file_permissions'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    file_id = Column(Integer, ForeignKey('files.id'), nullable=False)
    encryption_key = Column(BLOB, nullable=False)
    created_at = Column(DateTime, nullable=False)
    updated_at = Column(DateTime, nullable=False)

    user = relationship("Users", back_populates="file_permissions")
    file = relationship("Files", back_populates="file_permissions")

class Files(Base):
    """Files table to store file information."""
    __tablename__ = 'files'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    path = Column(String(512), nullable=False)
    uploaded_at = Column(DateTime, nullable=False, index=True)
    owner_id = Column(Integer, ForeignKey('users.id'), nullable=False)

    user = relationship("Users", back_populates="files")
    file_permissions = relationship(
        "FilePermissions",
        back_populates="file",
        cascade="all, delete-orphan"
    )
    file_metadata = relationship(
        "FileMetadata",
        back_populates="file",
        uselist=False, # Explicity a one-to-one relationship
        cascade="all, delete-orphan"
    )
    # Cascades: When a file is deleted, all its permissions and metadata are also deleted !!

class FileMetadata(Base):
    """File metadata table to store additional file information."""
    __tablename__ = 'file_metadata'

    id = Column(Integer, primary_key=True, autoincrement=True)
    file_id = Column(Integer, ForeignKey('files.id'), unique=True, nullable=False)
    size = Column(DECIMAL(10, 2), nullable=False)
    __table_args__ = (
        CheckConstraint('size <= 104857600', name='max_file_size_100mb'),
    )
    format = Column(String(50), nullable=False)
    last_updated_at = Column(DateTime, nullable=False)

    file = relationship("Files", back_populates="file_metadata")