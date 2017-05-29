package RSA;

import it.sauronsoftware.base64.Base64;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;


/**
 * RSA加密的库模块
 * Created by Suagr on 2017/5/28.
 */
public class RSALib {
    private BigInteger bigInteger;
    private KeyPairGenerator keyPairGenerator ;
    private KeyPair keyPair;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private int publicKeyLen;
    private DESKeySpec desKeySpec;
    private SecretKeyFactory secretKeyFactory;
    private SecretKey secretKey;
    private StringBuffer symmetryKetBits;


    public void setBigInteger(String str){
        this.bigInteger = new BigInteger(str);
    }

    // 构造和对一个大整数对象赋值
    public BigInteger getBigInteger(String str){
        this.setBigInteger(str);
        return bigInteger;
    }

    public BigInteger add(BigInteger val){
        return bigInteger.add(val);
    }

    public BigInteger subtract(BigInteger val){
        return bigInteger.subtract(val);
    }

    public BigInteger multiply(BigInteger val){
        return bigInteger.multiply(val);
    }

    public BigInteger divide(BigInteger val){
        return bigInteger.divide(val);
    }

    public BigInteger mod(BigInteger val){
        return bigInteger.mod(val);
    }

    // 乘方
    public BigInteger pow(int val){
        return bigInteger.pow(val);
    }

    // 判断是否是素数
    public boolean isPrime(){
        return bigInteger.isProbablePrime(1);
    }

    // 初始化密钥对
    public void initKeyPair(BigInteger val1 , BigInteger val2){
        String str = new String("rsa");
        val1 = val1.subtract(new BigInteger("1"));
        val2 = val2.subtract(new BigInteger("1"));
        BigInteger val = val1.multiply(val2);
        int len = val.intValue();
        if(len<512 || len>3000){
            len = 1024;
            publicKeyLen = len;
        }
        try {
            this.keyPairGenerator = KeyPairGenerator.getInstance(str); // 根据str选择加密算法
            keyPairGenerator.initialize(len); // 密钥长度
            this.keyPair = keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    // 获取公钥长度
    public int getPublicKeyLen(){return this.publicKeyLen;}

    // 获取公钥
    public PublicKey getRSAPublicKey(){
        // 创建密钥对
        this.publicKey = keyPair.getPublic();
        return this.publicKey;
    }

    // 获取公钥的编码字符串形式
    public String getRSAPublicKeyStr(){
        String keyStr = new String(Base64.encode(this.getRSAPublicKey().getEncoded()));
        return keyStr;
    }

    public PrivateKey getRSAPrivateKey(){
        try {
            this.privateKey = keyPair.getPrivate();
        }catch (Exception e){
            System.out.println("获取私钥前请先生成公钥");
        }
        return this.privateKey;
    }

    public String getRSAPrivateKeyStr(){
        String keyStr = new String(Base64.encode(this.getRSAPrivateKey().getEncoded()));
        return keyStr;
    }

    // 利用Integer的parseInt可以按进制转换数字的方法获取字节
    private byte bitToByte(String bits){
        if(bits.length()!=8)
            return 0;
        byte res = (byte)Integer.parseInt(bits,2);
        return res;
    }

    // 获取任意长度的对称密钥
    public String getSymmetryKeyBits(){
        return this.symmetryKetBits.toString();
    }

    public byte[] getSymmetryKey(int val){
        if(val!=80 && val!=128 && val!= 256 && val!=512)
            return null;
        int num = val/10;
        byte[] psd = new byte[num];
        int i=0;
        Random rand = new Random();
        for(int j=0;j<num;j++){
            StringBuffer sb = new StringBuffer();
            for(i=0;i<8;i++){
                sb.append((char)(rand.nextInt(2)+48));
            }
            String bits = sb.toString();
            if(this.symmetryKetBits==null)
                this.symmetryKetBits = new StringBuffer();
            this.symmetryKetBits.append(bits);
            psd[j] = this.bitToByte(bits);
        }
        return psd;
    }

    /**
     * 使用RSA的公钥进行加密
     * @param txt 明文
     * @param publicKey 公钥
     * @return
     */
    public byte[] RSAEncode(byte[] txt,PublicKey publicKey){
        byte[] encode = new byte[16000];
        try {
            Cipher cipher = Cipher.getInstance("rsa");
            cipher.init(Cipher.ENCRYPT_MODE,publicKey);
            encode = cipher.doFinal(txt);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("没有该加密算法");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            System.out.println(txt.length);
            e.printStackTrace();
        }
        return encode;
    }

    /**
     * 使用RSA的公钥和私钥进行解密
     * @param cipherTxt 密文
     * @param publicKey 公钥
     * @param privateKey 私钥
     * @return
     */
    public byte[] RSADecode(byte[] cipherTxt,PublicKey publicKey,PrivateKey privateKey){
        byte[] res = new byte[16000];
        try {
            Cipher cipher = Cipher.getInstance("rsa");
            cipher.init(Cipher.DECRYPT_MODE,privateKey);
            res = cipher.doFinal(cipherTxt);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            System.out.println(cipherTxt.length);
            e.printStackTrace();
        }
        System.out.println(this.byteToBits(res));
        return res;
    }

    private String byteToBits(byte[] bytes){
        StringBuffer sb = new StringBuffer();
        int i=0;
        for(byte b : bytes) {
            sb.append((bytes[i] >> 7) & 0x1)
                    .append((bytes[i] >> 6) & 0x1)
                    .append((bytes[i] >> 5) & 0x1)
                    .append((bytes[i] >> 4) & 0x1)
                    .append((bytes[i] >> 3) & 0x1)
                    .append((bytes[i] >> 2) & 0x1)
                    .append((bytes[i] >> 1) & 0x1)
                    .append((bytes[i] >> 0) & 0x1);
            i++;
        }
        return sb.toString();
    }
}
