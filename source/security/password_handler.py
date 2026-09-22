"""비밀번호 해시 처리"""
import bcrypt


def hash_password(password: str) -> str:
    """평문 비밀번호를 무작위 salt가 포함된 bcrypt 해시로 변환한다."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    """입력 비밀번호가 저장된 bcrypt 해시와 일치하는지 확인한다."""
    return bcrypt.checkpw(password.encode(), hashed.encode())
