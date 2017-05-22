package com.zyh;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RsaUtil {
	private static final String RSA = "RSA";// 非对称加密密钥算法
	private static final String ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";//加密填充方式

	/**
	 * 根据秘钥长度随机生成RSA密钥对
	 * @param keyLength 秘钥长度(范围为512~2048，一般为1024)
	 * @return 			生成的密钥对
	 */
	public static KeyPair getKeyPair(int keyLength){
		if(keyLength > 512 & keyLength < 2048){
			try {
				KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA);
				kpg.initialize(keyLength);
		        return kpg.genKeyPair();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
		}
		return null;
	}
	
	/**
	 * 公钥加密算法
	 * @param data 		(字符串)明文
	 * @param publicKey (RSAPublicKey)公钥
	 * @return 			(字符串)密文
	 */
	public static String encryptByPublicKey(String data, RSAPublicKey publicKey){
		if(data != null & publicKey != null ){
			try {
				byte[] cipherText = encryptByPublicKey(data.getBytes("UTF-8"), publicKey.getEncoded());
				return Base64.getEncoder().encodeToString(cipherText);
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
		}
		return null;
	}
	
	/**
	 * 公钥加密算法
	 * @param data 		(字节数组)明文
	 * @param publicKey (字节数组)公钥
	 * @return  		(字节数组)密文
	 */
	public static byte[] encryptByPublicKey(byte[] data, byte[] publicKey) {
		if(data != null & publicKey != null){
			try {
				//得到公钥
				X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
				KeyFactory kf = KeyFactory.getInstance(RSA);
				PublicKey keyPublic = kf.generatePublic(keySpec);
				// 加密数据
		        Cipher cp = Cipher.getInstance(ECB_PKCS1_PADDING);
		        cp.init(Cipher.ENCRYPT_MODE, keyPublic);
		        
		        return cp.doFinal(data);
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				e.printStackTrace();
			}
		}
        return null;
    }
	
	/**
	 * 私钥加密算法
	 * @param data 		 (字符串)明文
	 * @param privateKey (RSAPrivateKey)私钥
	 * @return 			 (字符串)密文
	 */
	public static String encryptByPrivateKey(String data, RSAPrivateKey privateKey) {
		if(data != null & privateKey != null){
			try {
				byte[] cipherText = encryptByPrivateKey(data.getBytes("UTF-8"), privateKey.getEncoded());
				return Base64.getEncoder().encodeToString(cipherText);
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
		}
		return null;
	}
	
	/**
	 * 私钥加密算法
	 * @param data 		 (字节数组)明文
	 * @param privateKey (字节数组)私钥
	 * @return 			 (字节数组)密文
	 */
	public static byte[] encryptByPrivateKey(byte[] data, byte[] privateKey) {
		if(data != null & privateKey != null){
			try {
		        // 得到私钥
		        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
				KeyFactory kf = KeyFactory.getInstance(RSA);
				PrivateKey keyPrivate = kf.generatePrivate(keySpec);
		        // 数据加密
		        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
		        cipher.init(Cipher.ENCRYPT_MODE, keyPrivate);
		        return cipher.doFinal(data);
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				e.printStackTrace();
			}
		}
        return null;
    }
	
	/**
	 * 公钥解密算法
	 * @param encrypted (字符串)密文
	 * @param publicKey (RSAPublicKey)公钥
	 * @return 			(字符串)明文
	 */
	public static String decryptByPublicKey(byte[] encrypted, RSAPublicKey publicKey) {
		if(encrypted != null & publicKey != null){
			try {
				byte[] bytes = Base64.getDecoder().decode(encrypted);
				return new String(decryptByPublicKey(bytes, publicKey.getEncoded()),"UTF-8");
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
		}
		return null;
	}
	
	
	/**
	 * 公钥解密算法
	 * @param encrypted (字节数组)密文
	 * @param publicKey (字节数组)公钥
	 * @return 			(字节数组)明文
	 */
	public static byte[] decryptByPublicKey(byte[] encrypted, byte[] publicKey) {
		if(encrypted != null & publicKey != null){
			try {
				// 得到公钥
				X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
				KeyFactory kf = KeyFactory.getInstance(RSA);
				PublicKey keyPublic = kf.generatePublic(keySpec);
		        // 数据解密
		        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
		        cipher.init(Cipher.DECRYPT_MODE, keyPublic);
		        return cipher.doFinal(encrypted);
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				e.printStackTrace();
			}
		}
        return null;
    }
	
	/**
	 * 私钥解密算法
	 * @param encrypted  (字符串)密文
	 * @param privateKey (RSAPrivateKey)私钥
	 * @return 			 (字符串)解密后的明文
	 */
	public static String decryptByPrivateKey(String encrypted, RSAPrivateKey privateKey) {
		if(encrypted != null & privateKey != null){
			try {
				byte[] bytes = Base64.getDecoder().decode(encrypted);
				return new String(decryptByPrivateKey(bytes, privateKey.getEncoded()),"UTF-8");
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
		}
		return null;
	}
	
	/**
	 * 私钥解密算法
	 * @param encrypted  (字节数组)密文
	 * @param privateKey (字节数组)私钥
	 * @return           (字节数组)明文
	 */
	public static byte[] decryptByPrivateKey(byte[] encrypted, byte[] privateKey) {
		if(encrypted != null & privateKey != null){
			try {
				// 得到私钥
		        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
		        KeyFactory kf = KeyFactory.getInstance(RSA);
		        PrivateKey keyPrivate = kf.generatePrivate(keySpec);
		        // 解密数据
		        Cipher cp = Cipher.getInstance(ECB_PKCS1_PADDING);
		        cp.init(Cipher.DECRYPT_MODE, keyPrivate);
		        byte[] arr = cp.doFinal(encrypted);
		        return arr;
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				e.printStackTrace();
			}
		}
        return null;
    }
}
