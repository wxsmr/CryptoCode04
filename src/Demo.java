import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class Demo {
    String key = "c190604";//设定的字符串密钥
    String data = "南昌的冬天忒冷了";
    static String str = "hl";//字符串

    /**
     * 程序的主函数
     *
     * @param args
     */
    public static void main(String[] args) {
        System.out.println(str);
        Demo demo = new Demo();
        System.out.println(demo.key);
        System.out.println(demo.data);
        //加密
        byte[] cipherText = demo.encrypt(demo.key.getBytes(), demo.data.getBytes());
        System.out.println(cipherText);//[B@4ec6a292

    }

    /**
     * DES算法的封装
     *
     * @param key  des算法的密钥
     * @param data 要操作的数据，明文或者密文
     * @param mode des算法的操作模式，Cipher.ENCRYPT_MODE 或 Cipher.DECRYPT_MODE
     * @return byte数组，加密后的密文或者解密后的明文
     */
    public byte[] desOperation(byte[] key, byte[] data, int mode) {
        try {
            DESKeySpec spec = new DESKeySpec(key);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
            SecretKey secretKey = factory.generateSecret(spec);
            //执行的cipher
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(mode, secretKey);
            return cipher.doFinal(data);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        //、四声
        return null;
    }

    //函数一：加密
    public byte[] encrypt(byte[] key, byte[] data) {
        //面向百度编程：java des
        //闻道有先后，术业有专攻，如是而已
        //善：论迹不论心
        //恶：论心不论迹
        try {
            //DES的秘钥生成
            DESKeySpec desKeySpec = new DESKeySpec(key);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("AES");
            SecretKey secretkey = secretKeyFactory.generateSecret(desKeySpec);
            //执行cipher加密动作的实例
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.ENCRYPT_MODE, secretkey);
            //执行最后的加密
            return cipher.doFinal(data);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } finally {
            //最终的逻辑处理

        }

        //返回值语句
        //攮：nang
        return null;//代表空，没有
    }

    //函数二：解密
    public byte[] decrypt(byte[] cipherTxt, byte[] key) {
        try {
            DESKeySpec spec = new DESKeySpec(key);//des密钥的初始化
            //标准的加密算法工厂,DES算法
            SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
            SecretKey secretKey = factory.generateSecret(spec);
            //执行解密 Cipher
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            cipher.doFinal(cipherTxt);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }
}

