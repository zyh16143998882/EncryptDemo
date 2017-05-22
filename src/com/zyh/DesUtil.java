package com.zyh;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class DesUtil {
	private final static String ALGORITHM = "DES";//DES是加密方式
	private final static String TRANSFORMATION = "DES/CBC/PKCS5Padding";//DES是加密方式 CBC是工作模式 PKCS5Padding是填充模式
	private final static String IVPARAMETERSPEC = "12345678";//初始化向量参数，AES 为16bytes. DES 为8bytes.

	/**
	 * 通过输入的密码生成DES加密的Key
	 * @param password 输入的密码
	 * @return DES加密所需要的Key对象
	 */
	public static Key getKey(String password){
		if(password != null){
			try {
				DESKeySpec dks = new DESKeySpec(password.getBytes());
				//创建一个密匙工厂，然后用它把DESKeySpec转换成SecretKey，这个SecretKey就是加密时使用的Key
				SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
		        return keyFactory.generateSecret(dks);
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				e.printStackTrace();
			}
		}
        return null;
	}
	
	
	/**
	 * DES加密函数
	 * @param password （String对象）输入的密码，用于生成DES的秘钥
	 * @param data     （String对象）待加密的数据
	 * @return         （String对象）加密后的数据
	 */
	public static String encrypt(String password , String data){
		if(password != null & data != null){
			try {
				return encrypt(getKey(password) , data.getBytes("UTF-8"));
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}
	
	
	/**
	 * DES加密函数
	 * @param key    （Key对象）DES加密所用的key
	 * @param data   （byte数组）待加密的数据的byte数组
	 * @return       （String对象）加密后的数据
	 */
	public static String encrypt(Key key , byte[] data){
		if(key != null & data != null){
			try {
				//声明加密处理类，并指定转换名称
				Cipher cipher = Cipher.getInstance(TRANSFORMATION);
				//用密匙和向量初始化此加密对象
				cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IVPARAMETERSPEC.getBytes()));
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
	 * DES解密函数
	 * @param password （String对象）输入的密码，用于生成DES的秘钥
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
	 * DES解密函数
	 * @param key    （Key对象）DES解密所用的key
	 * @param data   （byte数组）待解密的数据的byte数组
	 * @return       （String对象）解密后的数据
	 */
	public static String decrypt(Key key , byte[] data){
		if(key != null & data != null){
			try {
				Cipher cipher = Cipher.getInstance(TRANSFORMATION);
				IvParameterSpec iv = new IvParameterSpec(IVPARAMETERSPEC.getBytes());
				cipher.init(Cipher.DECRYPT_MODE, key, iv);
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
			} catch (InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}
}
