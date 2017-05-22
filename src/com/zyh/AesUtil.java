package com.zyh;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesUtil {
	private final static String ALGORITHM = "AES";//DES是加密方式
	private final static String TRANSFORMATION = "AES/CBC/PKCS5Padding";


	/**
	 * 通过输入的密码生成AES加密的Key的函数
	 * @param password 输入的密码
	 * @return AES加密所需要的Key对象
	 */
	public static Key getKey(String password){
		if(password != null){
			try {
				KeyGenerator kgen = KeyGenerator.getInstance("AES");  
	            kgen.init(128, new SecureRandom(password.getBytes()));  
	            SecretKey secretKey = kgen.generateKey();  
	            byte[] raw = secretKey.getEncoded();
	            SecretKeySpec skeySpec = new SecretKeySpec(raw, ALGORITHM);
	            return skeySpec;
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
		}
        return null;
	}
	
	
	/**
	 * AES加密函数
	 * @param password （String对象）输入的密码，用于生成AES的秘钥
	 * @param data     （String对象）待加密的数据
	 * @return         （String对象）加密后的数据
	 */
	public static String encrypt(String password , String data){
		if(password != null & data != null){
			try {
				return encrypt(getKey(password) , data.getBytes("UTF-8"));
			} catch (UnsupportedEncodingException e) { 
				e.printStackTrace();
			}
		}
		return null;
	}
	
	
	/**
	 * AES加密函数
	 * @param key    （Key对象）AES加密所用的key
	 * @param data   （byte数组）待加密的数据的byte数组
	 * @return       （String对象）加密后的数据
	 */
	public static String encrypt(Key key , byte[] data){
		if(key != null & data != null){
			try {
				//声明加密处理类，并指定转换名称
				Cipher cipher = Cipher.getInstance(TRANSFORMATION);
				//用密匙和向量初始化此加密对象
				cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[cipher.getBlockSize()]));
				//通过生成的加密对象对源数据进行加密，返回加密后的字节数组
				byte[] bytes = cipher.doFinal(data);
				//最后再使用Base64进行一次编码，返回编码后的String
				return Base64.getEncoder().encodeToString(bytes);
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}
	
	
	/**
	 * AES解密函数
	 * @param password （String对象）输入的密码，用于生成AES的秘钥
	 * @param data     （String对象）加密后的数据
	 * @return         （String对象）解密后的数据
	 */
	public static String decrypt(String password , String data){
		if(password != null & data != null){
			byte[] bytes = Base64.getDecoder().decode(data);
			return decrypt(getKey(password), bytes);
		}
		return null;
	}
	
	
	/**
	 * AES解密函数
	 * @param key    （Key对象）AES解密所用的key
	 * @param data   （byte数组）待解密的数据的byte数组
	 * @return       （String对象）解密后的数据
	 */
	public static String decrypt(Key key , byte[] data){
		if(key != null & data != null){
			try {
				Cipher cipher = Cipher.getInstance(TRANSFORMATION);
				cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(new byte[cipher.getBlockSize()]));
				byte[] bytes = cipher.doFinal(data);
				
				return new String(bytes,"UTF-8");
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}
}
