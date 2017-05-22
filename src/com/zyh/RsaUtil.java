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
	private static final String RSA = "RSA";// �ǶԳƼ�����Կ�㷨
	private static final String ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";//������䷽ʽ

	/**
	 * ������Կ�����������RSA��Կ��
	 * @param keyLength ��Կ����(��ΧΪ512~2048��һ��Ϊ1024)
	 * @return 			���ɵ���Կ��
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
	 * ��Կ�����㷨
	 * @param data 		(�ַ���)����
	 * @param publicKey (RSAPublicKey)��Կ
	 * @return 			(�ַ���)����
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
	 * ��Կ�����㷨
	 * @param data 		(�ֽ�����)����
	 * @param publicKey (�ֽ�����)��Կ
	 * @return  		(�ֽ�����)����
	 */
	public static byte[] encryptByPublicKey(byte[] data, byte[] publicKey) {
		if(data != null & publicKey != null){
			try {
				//�õ���Կ
				X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
				KeyFactory kf = KeyFactory.getInstance(RSA);
				PublicKey keyPublic = kf.generatePublic(keySpec);
				// ��������
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
	 * ˽Կ�����㷨
	 * @param data 		 (�ַ���)����
	 * @param privateKey (RSAPrivateKey)˽Կ
	 * @return 			 (�ַ���)����
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
	 * ˽Կ�����㷨
	 * @param data 		 (�ֽ�����)����
	 * @param privateKey (�ֽ�����)˽Կ
	 * @return 			 (�ֽ�����)����
	 */
	public static byte[] encryptByPrivateKey(byte[] data, byte[] privateKey) {
		if(data != null & privateKey != null){
			try {
		        // �õ�˽Կ
		        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
				KeyFactory kf = KeyFactory.getInstance(RSA);
				PrivateKey keyPrivate = kf.generatePrivate(keySpec);
		        // ���ݼ���
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
	 * ��Կ�����㷨
	 * @param encrypted (�ַ���)����
	 * @param publicKey (RSAPublicKey)��Կ
	 * @return 			(�ַ���)����
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
	 * ��Կ�����㷨
	 * @param encrypted (�ֽ�����)����
	 * @param publicKey (�ֽ�����)��Կ
	 * @return 			(�ֽ�����)����
	 */
	public static byte[] decryptByPublicKey(byte[] encrypted, byte[] publicKey) {
		if(encrypted != null & publicKey != null){
			try {
				// �õ���Կ
				X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
				KeyFactory kf = KeyFactory.getInstance(RSA);
				PublicKey keyPublic = kf.generatePublic(keySpec);
		        // ���ݽ���
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
	 * ˽Կ�����㷨
	 * @param encrypted  (�ַ���)����
	 * @param privateKey (RSAPrivateKey)˽Կ
	 * @return 			 (�ַ���)���ܺ������
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
	 * ˽Կ�����㷨
	 * @param encrypted  (�ֽ�����)����
	 * @param privateKey (�ֽ�����)˽Կ
	 * @return           (�ֽ�����)����
	 */
	public static byte[] decryptByPrivateKey(byte[] encrypted, byte[] privateKey) {
		if(encrypted != null & privateKey != null){
			try {
				// �õ�˽Կ
		        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
		        KeyFactory kf = KeyFactory.getInstance(RSA);
		        PrivateKey keyPrivate = kf.generatePrivate(keySpec);
		        // ��������
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
