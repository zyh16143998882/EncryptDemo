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
	private final static String ALGORITHM = "AES";//DES�Ǽ��ܷ�ʽ
	private final static String TRANSFORMATION = "AES/CBC/PKCS5Padding";


	/**
	 * ͨ���������������AES���ܵ�Key�ĺ���
	 * @param password ���������
	 * @return AES��������Ҫ��Key����
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
	 * AES���ܺ���
	 * @param password ��String������������룬��������AES����Կ
	 * @param data     ��String���󣩴����ܵ�����
	 * @return         ��String���󣩼��ܺ������
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
	 * AES���ܺ���
	 * @param key    ��Key����AES�������õ�key
	 * @param data   ��byte���飩�����ܵ����ݵ�byte����
	 * @return       ��String���󣩼��ܺ������
	 */
	public static String encrypt(Key key , byte[] data){
		if(key != null & data != null){
			try {
				//�������ܴ����࣬��ָ��ת������
				Cipher cipher = Cipher.getInstance(TRANSFORMATION);
				//���ܳ׺�������ʼ���˼��ܶ���
				cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[cipher.getBlockSize()]));
				//ͨ�����ɵļ��ܶ����Դ���ݽ��м��ܣ����ؼ��ܺ���ֽ�����
				byte[] bytes = cipher.doFinal(data);
				//�����ʹ��Base64����һ�α��룬���ر�����String
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
	 * AES���ܺ���
	 * @param password ��String������������룬��������AES����Կ
	 * @param data     ��String���󣩼��ܺ������
	 * @return         ��String���󣩽��ܺ������
	 */
	public static String decrypt(String password , String data){
		if(password != null & data != null){
			byte[] bytes = Base64.getDecoder().decode(data);
			return decrypt(getKey(password), bytes);
		}
		return null;
	}
	
	
	/**
	 * AES���ܺ���
	 * @param key    ��Key����AES�������õ�key
	 * @param data   ��byte���飩�����ܵ����ݵ�byte����
	 * @return       ��String���󣩽��ܺ������
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
