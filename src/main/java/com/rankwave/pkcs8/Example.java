package com.rankwave.pkcs8;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Example {
	public static byte[] pbkdf1(String password, byte[] salt, int iterationCount) throws NoSuchAlgorithmException {
		byte[] dk = new byte[20];
		MessageDigest md = MessageDigest.getInstance("SHA1");
		md.update(password.getBytes());
		md.update(salt);
		dk = md.digest();
		for (int i = 1; i < iterationCount; i++) {
			dk = md.digest(dk);
		}
		return dk;
	}
}
