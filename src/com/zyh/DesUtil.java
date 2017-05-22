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
	private final static String ALGORITHM = "DES";//DES�Ǽ��ܷ�ʽ
	private final static String TRANSFORMATION = "DES/CBC/PKCS5Padding";//DES�Ǽ��ܷ�ʽ CBC�ǹ���ģʽ PKCS5Padding�����ģʽ
	private final static String IVPARAMETERSPEC = "12345678";//��ʼ������������AES Ϊ16bytes. DES Ϊ8bytes.

	/**
	 * ͨ���������������DES���ܵ�Key
	 * @param password ���������
	 * @return DES��������Ҫ��Key����
	 */
	public static Key getKey(String password){
		if(password != null){
			try {
				DESKeySpec dks = new DESKeySpec(password.getBytes());
				//����һ���ܳ׹�����Ȼ��������DESKeySpecת����SecretKey�����SecretKey���Ǽ���ʱʹ�õ�Key
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
	 * DES���ܺ���
	 * @param password ��String������������룬��������DES����Կ
	 * @param data     ��String���󣩴����ܵ�����
	 * @return         ��String���󣩼��ܺ������
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
	 * DES���ܺ���
	 * @param key    ��Key����DES�������õ�key
	 * @param data   ��byte���飩�����ܵ����ݵ�byte����
	 * @return       ��String���󣩼��ܺ������
	 */
	public static String encrypt(Key key , byte[] data){
		if(key != null & data != null){
			try {
				//�������ܴ����࣬��ָ��ת������
				Cipher cipher = Cipher.getInstance(TRANSFORMATION);
				//���ܳ׺�������ʼ���˼��ܶ���
				cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IVPARAMETERSPEC.getBytes()));
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
	 * DES���ܺ���
	 * @param password ��String������������룬��������DES����Կ
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
	 * DES���ܺ���
	 * @param key    ��Key����DES�������õ�key
	 * @param data   ��byte���飩�����ܵ����ݵ�byte����
	 * @return       ��String���󣩽��ܺ������
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
