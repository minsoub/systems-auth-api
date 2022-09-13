package com.bithumbsystems.auth.api.config.constant;

public final class ParameterStoreConstant {

  public static final String DB_URL = "dburl";
  public static final String DB_USER = "user";
  public static final String DB_PORT = "port";
  public static final String DB_NAME = "dbname";
  public static final String DB_PASSWORD = "passwd";

  public static final String REDIS_HOST = "host";
  public static final String REDIS_PORT = "port";
  public static final String REDIS_TOKEN = "token";

  // 고객 관리형 키
  public static final String KMS_ALIAS_NAME = "key";
  public static final String CRYPT_ALIAS_NAME = "key";
  public static final String LRC_CRYPT_ALIAS_NAME = "crypto-key";
  public static final String CPC_CRYPT_ALIAS_NAME = "crypto-key";
  public static final String MAIL_SENDER = "mail_sender";
  public static final String SMTP_USERNAME = "smtp_username";
  public static final String SMTP_PASSWORD = "smtp_password";
  public static final String JWT_SECRET_KEY = "jwt_secret_key";
  public static final String JWT_ACCESS_EXPIRATION = "jwt_access_expiration";
  public static final String JWT_REFRESH_EXPIRATION = "jwt_refresh_expiration";

}