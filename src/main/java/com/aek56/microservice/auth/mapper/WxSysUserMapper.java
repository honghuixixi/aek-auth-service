package com.aek56.microservice.auth.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import com.aek56.microservice.auth.dao.CrudDao;
import com.aek56.microservice.auth.entity.WxSysUser;
import com.aek56.microservice.auth.weixin.token.WeiXinAccessToken;

/**
 * 系统用户与微信绑定数据Mapper类
 *	
 * @author HongHui
 * @date   2017年12月1日
 */
@Mapper
public interface WxSysUserMapper extends CrudDao<WxSysUser> {

	/**
	 * 保存WxSysUser
	 * @param wxSysUser
	 */
	public void insertWxSysUser(@Param("wxSysUser") WxSysUser wxSysUser);
	
	/**
	 * 查询openId是否已经绑定系统用户
	 * @return
	 */
	public int countWxSysUser(@Param("openId") String openId);
	
	/**
	 * 查询openId绑定系统用户
	 * @param openId
	 * @return
	 */
	public WxSysUser selectWxSysUserByOpenId(@Param("openId") String openId);
	
	/**
	 * 查询unionId绑定系统用户
	 * @param unionId
	 * @return
	 */
	public WxSysUser selectWxSysUserByUnionId(@Param("unionId") String unionId);
	
	/**
	 * 查询miniOpenId绑定系统用户
	 * @param miniOpenId
	 * @return
	 */
	public WxSysUser selectWxSysUserByMiniOpenId(@Param("miniOpenId") String miniOpenId);
	
	/**
	 * 查询userId绑定系统用户
	 * @param userId
	 * @return
	 */
	public WxSysUser selectWxSysUserByUserId(@Param("userId") Long userId);
	
	/**
	 * 更新绑定信息
	 * @param wxSysUser
	 */
	public void updateWxSysUser(@Param("wxSysUser")WxSysUser wxSysUser);
	
}
