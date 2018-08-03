package com.bb;

public class AES128Test {

	public static void main(String[] args) {
		try {
			AesUtil aesUtil = new AesUtil();
			
			String encString = aesUtil.encrypt("pass1234");
			System.out.println("encString : " + encString);
			
			String decString = aesUtil.decrypt(encString);
			System.out.println("decString : " + decString);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
