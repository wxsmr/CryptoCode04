package rsa;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * 该类用于实现RSA算法的操作，包括密钥生成，加解密,签名验证等操作
 */
public class RSACode {

    static String data = "南昌的冬天忒冷了";

    public static void main(String[] args) {
        // TODO: 2020/11/26 main为程序的入口函数
        System.out.println("hello world");
        RSACode code = new RSACode();
        //密钥生成
        KeyPair keyPair = code.createKey(1024);
        //加密后的密文
        byte[] cipherTxt = code.encrypt(data.getBytes(), keyPair.getPublic());
        System.out.println(cipherTxt);//[B@33a10788
        //调用解密方法进行解密
        byte[] originalTxt = code.decrypt(cipherTxt, keyPair.getPrivate());
    }
  //======================通过读取密钥文件恢复公钥和私钥===========//

    /**
     * 根据pem文件恢复公钥
     *
     * @param file_name  文件名称
     * @return   公钥对象
     */
    public PrivateKey readPriByPem(String file_name){
        //TODO:2020/11/30 读取pem文件，恢复公钥
        return null;
    }

    /**
     * 读取der文件，恢复成私钥
     *
     * @param file_name 文件名称
     * @return  公钥对象
     */
    public PublicKey loadPubByDer(String file_name){
        try {
            byte[] pubBytes = Files.readAllBytes(Paths.get(file_name));
            X509EncodedKeySpec spec =new X509EncodedKeySpec(pubBytes);
            KeyFactory factory =KeyFactory.getInstance("RSA");
            return factory.generatePublic(spec);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 读取der文件,恢复成私钥
     *
     * @param file_name 私钥文件
     * @return   私钥对象
     */
    public PrivateKey loadPriByDer(String file_name){
        /**
         * 字节流:任意的文件,把文件内容都城byte[]
         * 字符流:只对针对你文档/文本,readString,readLine
         */
       try{
           //从文件当中读取私钥字节数据
           byte[] priBytes =Files.readAllBytes(Paths.get(file_name));
           X509EncodedKeySpec spec =new X509EncodedKeySpec(priBytes);
           //工厂类:KeyFactory
           KeyFactory factory = KeyFactory.getInstance("RSA");
           //生成私钥
           return factory.generatePrivate(spec);
       } catch (IOException e) {
           e.printStackTrace();
       } catch (NoSuchAlgorithmException e) {
           e.printStackTrace();
       } catch (InvalidKeySpecException e) {
           e.printStackTrace();
       }
       return null;
    }
    //================MD5的hash计算=============//
    /**
     * 对原文数据进行MD5的hash计算
     *
     * @param data 原文
     * @return MD5的hash值
     */
    public byte[] md5Hash(byte[] data) {
        //hash算法: 消息摘要, Message Digest
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    //=========================实现 私钥签名，公钥验签==========================//

    /**
     * 对签名进行验证
     *
     * @param sign 要验证的签名数据
     * @param data 原文
     * @param pub  公钥
     * @return 签名验证是否通过
     */
    public boolean verify(byte[] sign, byte[] data, PublicKey pub) {
        //rsa.VerifyPKCS1v15(pub,hash,hashed,sign)
        try {
            Signature signature = Signature.getInstance("MD5withRSA");
            signature.initVerify(pub);
            byte[] hash = md5Hash(data);
            signature.update(hash);//原文hash
            return signature.verify(sign);//验证签名
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        return false;
    }

    /**
     * 对数据进行签名
     *
     * @param data 原文
     * @param pri  私钥
     * @return 签名后的数据
     */
    public byte[] sign(byte[] data, PrivateKey pri) {
        //crypto/rsa crypto/des
        //rsa.SignPKCS1v15(rand,pri,hash,hasded)
        try {
            Signature signature = Signature.getInstance("MD5withRSA");
            signature.initSign(pri);//为签名工具设置私钥
            //对原文进行hash计算
            byte[] hash = md5Hash(data);
            signature.update(hash);//设置要签名的设置
            return signature.sign();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    //==============生成秘钥对=========//

    /**
     * 根据传入的秘钥生成的长度生成RSA的秘钥对
     *
     * @param size 秘钥的长度有两种选择，1024和2048
     * @return 返回生成的秘钥对
     */
    public KeyPair createKey(int size) {
        //工厂：factory，可以根据需求产生不同的类的实例
        //generate:生成，
        //instance：实例
        try {
            //秘钥生成器
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(size);//设置秘钥生成的长度
            KeyPair keyPair = generator.generateKeyPair();
            return keyPair;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    //=================公钥加密，私钥解密===============//

    /**
     * 使用RSA算法私钥对数据进行解密
     *
     * @param cipherTxt 要解密的密文
     * @param pri       私钥
     * @return 机密后的明文byte数组
     */
    public byte[] decrypt(byte[] cipherTxt, PrivateKey pri) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, pri);
            return cipher.doFinal(cipherTxt);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * 使用rsa的公钥对数据进行加密
     *
     * @param data 要加密的数据
     * @param pub  公钥
     */
    public byte[] encrypt(byte[] data, PublicKey pub) {
        //执行加密
        /**
         * 分工：检察院、法院、公安（干活）
         */
        //java中专门用于加密或者解密的类：Cipher
        try {
            Cipher cipher = Cipher.getInstance("RSA");//
            cipher.init(Cipher.ENCRYPT_MODE, pub);//设置cipher的工作模式
            return cipher.doFinal(data);//真正的加密
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }
}
