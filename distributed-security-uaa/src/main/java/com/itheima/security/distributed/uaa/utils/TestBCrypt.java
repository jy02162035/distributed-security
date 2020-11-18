package com.itheima.security.distributed.uaa.utils;

import org.springframework.security.crypto.bcrypt.BCrypt;

public class TestBCrypt {
    public static void test1() {
        //对原始密码加密
        String hashpw = BCrypt.hashpw("123", BCrypt.gensalt());
        System.out.println("hashpw == 【" + hashpw + "】");

        String secret = BCrypt.hashpw("secret", BCrypt.gensalt());
        System.out.println("secret == 【" + secret + "】");

        //校验原始密码和BCrypt密码是否一致
        boolean checkpw = BCrypt.checkpw("secret", "$2a$10$1pBmcn/b63gUfyV8h2a5beP4XQtY3/nVJzKSDVfrzwjWPl9BRW2/y");
        System.out.println(checkpw);
    }

    public static void main(String[] args) {
        TestBCrypt.test1();
    }
}