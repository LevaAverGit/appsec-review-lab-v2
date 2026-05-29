from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="APPSEC_", env_file=".env", extra="ignore")

    db_path: str = "lab.db"
    jwt_secret: str = "FAKE_JWT_SECRET_FOR_LAB_ONLY_NOT_FOR_PRODUCTION"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 30
    upload_dir: str = "/tmp/appsec_lab_uploads"
    max_upload_bytes: int = 1_048_576  # 1 MB
