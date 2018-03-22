package com.shiro.realms;

import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * Created by lyq on 2018/3/22.
 */

public class MyRealm extends AuthorizingRealm{
    //授权方法：获取授权信息
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        System.out.println("执行授权方法...");
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        //资源授权码
        //info.addStringPermission("productAdd");

        //进行通配符授权
        info.addStringPermission("product:*");

        //角色授权码
        info.addRole("admin");
        return info;
    }
    //认证方法：获取认证信息
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        System.out.println("执行认证方法...");
        //判断用户名是否存在， 判断密码是否正确
        //1.如果获取用户输入的账户信息？
        UsernamePasswordToken token = (UsernamePasswordToken)authenticationToken;
        String username = token.getUsername();
        //2.如果获取数据库的账户信息？
        //模拟数据库的账户信息
        String name = "jack";
        String password = "123";
        //判断用户名
        if(!username.equals(name)){
            return null; // shiro 底层自动抛出 UnknownAccountException
        }
        //判断密码
        /**
         * 参数一： principal， 用于把数据回传到 login 方法
         * 参数二： 数据库的密码
         * Shiro 底层对比密码的结果：
         * 1） 密码正确： 认证通过
         * 2） 密码不正确： 自动抛出 IncorrectCredentialsException
         * 参数三： realm 的名称， 只有在多个 realm 的是才会使用
         */
        return new SimpleAuthenticationInfo("callback",password,"");
    }
}
