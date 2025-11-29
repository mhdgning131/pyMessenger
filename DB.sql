CREATE IF NOT EXIST DATABASE My_Database; --Database creation

USE Data_base; -- Selecting the database

-- ----------------------------------------------------------
-- Script MYSQL
-- ----------------------------------------------------------


-- ----------------------------
-- Table: user
-- ----------------------------
CREATE TABLE user (
  username VARCHAR(50) NOT NULL,
  public_key TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL,
  last_login TIMESTAMP NOT NULL,
  is_online TINYINT(1) NOT NULL,
  login_attemps INT NOT NULL,
  locked_until TIMESTAMP NOT NULL,
  CONSTRAINT user_PK PRIMARY KEY (username)
)ENGINE=InnoDB;


-- ----------------------------
-- Table: session
-- ----------------------------
CREATE TABLE session (
  id_session INT NOT NULL,
  session_token TEXT NOT NULL,
  ip_address VARCHAR(45) NOT NULL,
  created_at TIMESTAMP NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  is_active TINYINT(1) NOT NULL,
  username VARCHAR(50) NOT NULL,
  CONSTRAINT session_PK PRIMARY KEY (id_session),
  CONSTRAINT session_username_FK FOREIGN KEY (username) REFERENCES user (username)
)ENGINE=InnoDB;


-- ----------------------------
-- Table: message
-- ----------------------------
CREATE TABLE message (
  id_message INT NOT NULL,
  receiver_username VARCHAR(50) NOT NULL,
  message_type VARCHAR(20) NOT NULL,
  encrypted_content TEXT NOT NULL,
  tag TEXT NOT NULL,
  timestamp TIMESTAMP NOT NULL,
  is_read TINYINT(1) NOT NULL,
  username VARCHAR(50) NOT NULL,
  CONSTRAINT message_PK PRIMARY KEY (id_message),
  CONSTRAINT message_username_FK FOREIGN KEY (username) REFERENCES user (username)
)ENGINE=InnoDB;