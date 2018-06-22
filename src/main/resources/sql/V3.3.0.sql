#添加启用开关字段
alter table wx_sys_user add column `enable` bit(1) DEFAULT b'1' COMMENT '是否启用(1=启用，0=禁用)';