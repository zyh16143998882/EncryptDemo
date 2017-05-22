/**
 * ���������������мӽ��ܹ�����
 */
package com.zyh;

import java.io.File;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class Test {
	private final static String Password = "zyhzyhzy";//ʹ�ô�����������Կ
	private static int RsaKeyLength = 1024;
	private static File file = new File("D:/test.txt");

	public static void main(String[] args) {
		String data = "����Ҫ���ܵ�Դ����";
		
		System.out.println("DES����ǰ������:" + data + "\n");
		
		System.out.println("--------------------------------------------------------");
		//DES����
		String desCipherText = DesUtil.encrypt(Password, data);
		System.out.println("DES���ܺ������:" + desCipherText);
		//DES����
		String desStr = DesUtil.decrypt(Password, desCipherText);
		System.out.println("DES���ܺ������:" + desStr + "\n");
		
		//AES����
		String aesCipherText = AesUtil.encrypt(Password, data);
		System.out.println("AES���ܺ������:" + aesCipherText);
		//AES����
		String aesStr = AesUtil.decrypt(Password, aesCipherText);
		System.out.println("DES���ܺ������:" + aesStr + "\n\n");
		System.out.println("--------------------------------------------------------");
		
		
		//�õ���Կ��
		KeyPair keyPair = RsaUtil.getKeyPair(RsaKeyLength);
		//��Կ
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		//˽Կ
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		
		//��Կ����
		String publicCipherText = RsaUtil.encryptByPublicKey(data, publicKey);
		System.out.println("RSA��Կ���ܺ������:" + publicCipherText);
		//˽Կ����
		String publicDestStr = RsaUtil.decryptByPrivateKey(publicCipherText, privateKey);
		System.out.println("RSA˽Կ���ܺ������:" + publicDestStr + "\n");
		
		//˽Կ����
		String privateCipherText = RsaUtil.encryptByPublicKey(data, publicKey);
		System.out.println("RSA˽Կ���ܺ������:" + privateCipherText);
		//��Կ����
		String privateDestStr = RsaUtil.decryptByPrivateKey(publicCipherText, privateKey);
		System.out.println("RSA��Կ���ܺ������:" + privateDestStr + "\n\n");
		
		System.out.println("--------------------------------------------------------");
		
		String strMD5 = MD5Util.md5(data);
		System.out.println("�ַ�����MD5ֵΪ��" + strMD5);
		
		String fileMD5 = MD5Util.md5(file);
		System.out.println("�ļ���MD5ֵΪ��" + fileMD5 + "\n");
		
		String hashStrMD5 = HashUtil.hash(data, "MD5");
		System.out.println("hash�㷨�ַ�����MD5ֵΪ��" + hashStrMD5);
		String hashStrSHA1 = HashUtil.hash(data, "SHA1");
		System.out.println("hash�㷨�ַ�����SHA1ֵΪ��" + hashStrSHA1 + "\n");
		
		String hashFileMD5 = HashUtil.hash(file, "MD5");
		System.out.println("hash�㷨�ļ���MD5ֵΪ��" + hashFileMD5);
		String hashFileSHA1 = HashUtil.hash(file, "SHA1");
		System.out.println("hash�㷨�ļ���SHA1ֵΪ��" + hashFileSHA1);
		
		
	}

}
