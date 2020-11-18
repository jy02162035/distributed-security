package com.itheima.security.distributed.order.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.itheima.security.distributed.order.model.UserDTO;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Administrator
 * @version 1.0
 **/
@RestController
public class OrderController {

    @GetMapping(value = "/r1")
    @PreAuthorize("hasAuthority('p1')")//拥有p1权限方可访问此url
    public String r1(){

        //获取用户身份信息
        String  userStr = (String) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        JSONObject userJson =  JSONObject.parseObject(userStr);
        UserDTO userDTO = JSON.toJavaObject(userJson, UserDTO.class);

        return userDTO.getFullname()+"访问资源1";
    }

}