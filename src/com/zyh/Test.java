/**
 * 此类用来测试所有加解密工具类
 */
package com.zyh;

import java.io.File;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class Test {
	private final static String Password = "zyhzyhzy";//使用此密码生成秘钥
	private static int RsaKeyLength = 1024;
	private static File file = new File("D:/test.txt");

	public static void main(String[] args) {
		String data = "我是要加密的源数据";
		
		System.out.println("DES加密前的数据:" + data + "\n");
		
		System.out.println("--------------------------------------------------------");
		//DES加密
		String desCipherText = DesUtil.encrypt(Password, data);
		System.out.println("DES加密后的数据:" + desCipherText);
		//DES解密
		String desStr = DesUtil.decrypt(Password, desCipherText);
		System.out.println("DES解密后的数据:" + desStr + "\n");
		
		//AES加密
		String aesCipherText = AesUtil.encrypt(Password, data);
		System.out.println("AES加密后的数据:" + aesCipherText);
		//AES解密
		String aesStr = AesUtil.decrypt(Password, aesCipherText);
		System.out.println("DES解密后的数据:" + aesStr + "\n\n");
		System.out.println("--------------------------------------------------------");
		
		
		//得到密钥对
		KeyPair keyPair = RsaUtil.getKeyPair(RsaKeyLength);
		//公钥
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		//私钥
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		
		//公钥加密
		String publicCipherText = RsaUtil.encryptByPublicKey(data, publicKey);
		System.out.println("RSA公钥加密后的数据:" + publicCipherText);
		//私钥解密
		String publicDestStr = RsaUtil.decryptByPrivateKey(publicCipherText, privateKey);
		System.out.println("RSA私钥解密后的数据:" + publicDestStr + "\n");
		
		//私钥加密
		String privateCipherText = RsaUtil.encryptByPublicKey(data, publicKey);
		System.out.println("RSA私钥加密后的数据:" + privateCipherText);
		//公钥解密
		String privateDestStr = RsaUtil.decryptByPrivateKey(publicCipherText, privateKey);
		System.out.println("RSA公钥解密后的数据:" + privateDestStr + "\n\n");
		
		System.out.println("--------------------------------------------------------");
		
		String strMD5 = MD5Util.md5(data);
		System.out.println("字符串的MD5值为：" + strMD5);
		
		String fileMD5 = MD5Util.md5(file);
		System.out.println("文件的MD5值为：" + fileMD5 + "\n");
		
		String hashStrMD5 = HashUtil.hash(data, "MD5");
		System.out.println("hash算法字符串的MD5值为：" + hashStrMD5);
		String hashStrSHA1 = HashUtil.hash(data, "SHA1");
		System.out.println("hash算法字符串的SHA1值为：" + hashStrSHA1 + "\n");
		
		String hashFileMD5 = HashUtil.hash(file, "MD5");
		System.out.println("hash算法文件的MD5值为：" + hashFileMD5);
		String hashFileSHA1 = HashUtil.hash(file, "SHA1");
		System.out.println("hash算法文件的SHA1值为：" + hashFileSHA1);
		
		
	}

}
