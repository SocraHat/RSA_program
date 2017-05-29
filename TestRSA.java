package RSA;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * Created by Suagr on 2017/5/28.
 */
public class TestRSA {
    static RSALib lib = new RSALib();

    public static void main(String[] args){
        BigInteger bigInteger= lib.getBigInteger("97");
        lib.initKeyPair(bigInteger,lib.getBigInteger("89"));

        System.out.println("------------------ALICE加密----------------------");
        System.out.println("512位对称密钥：");
        byte[] symKey =  lib.getSymmetryKey(512);
        System.out.println(lib.getSymmetryKeyBits());
        System.out.println(new String(symKey));

        System.out.println("RSA公钥");
        String publicKeyStr = lib.getRSAPublicKeyStr();
        PublicKey publicKey = lib.getRSAPublicKey();
        System.out.println(publicKeyStr);
        System.out.println("公钥长度为：" + lib.getPublicKeyLen());

        System.out.println("RSA私钥：");
        String privateKeyStr = lib.getRSAPrivateKeyStr();
        PrivateKey privateKey = lib.getRSAPrivateKey();
        System.out.println(privateKeyStr);

        System.out.println("--------------------BOB解密-----------------------");

        System.out.println("公钥加密后的对称密钥的密文：");
        byte[] cipherTxt = lib.RSAEncode(symKey,publicKey);
        System.out.println(new String(cipherTxt));

        System.out.println("私钥解密后的对称密钥的明文：");
        byte[] txt = lib.RSADecode(cipherTxt,publicKey,privateKey);
        System.out.println(new String(txt));

        System.out.println("对称密钥加密解密后是否相等？");
        System.out.println(Arrays.equals(txt,symKey));
    }
}
