package com.rankwave.pkcs8;

import static com.rankwave.pkcs8.CryptUtil.derivePKCS12Key;
import static com.rankwave.pkcs8.CryptUtil.hash;
import static com.rankwave.pkcs8.CryptUtil.pbkdf1;
import static com.rankwave.pkcs8.CryptUtil.printBytes;
import static org.apache.commons.lang3.ArrayUtils.subarray;

public interface PbeKeyDeriver {
	default byte[][] derive(MDSpec mdSpec, String password, byte[] salt, int iter, int keyLen, int ivLen) {
		try {
			return _derive(mdSpec, password, salt, iter, keyLen, ivLen);
		}
		catch (Exception e) {
			throw e instanceof RuntimeException ? (RuntimeException)e : new RuntimeException(e);
		}
	}
	
	byte[][] _derive(MDSpec mdSpec, String password, byte[] salt, int iter, int keyLen, int ivLen) throws Exception;
	
	public static PbeKeyDeriver PKCS12 = new PbeKeyDeriver() {

		@Override
		public byte[][] _derive(MDSpec mdSpec, String password, byte[] salt, int iter, int keyLen, int ivLen) throws Exception{
			String pass = password + '\0';
			
			byte[] key = derivePKCS12Key(mdSpec, pass, salt, 1, iter, keyLen);
			printBytes("key", key);
	
			byte[] iv = derivePKCS12Key(mdSpec, pass, salt, 2, iter, ivLen);
			printBytes("iv", iv);
			
			return new byte[][] { key, iv };
		}
	};
	
	public static PbeKeyDeriver SEED = new PbeKeyDeriver() {
		
		@Override
		public byte[][] _derive(MDSpec mdSpec, String password, byte[] salt, int iter, int keyLen, int ivLen) throws Exception {
			// 추출키(DK) 생성
			byte[] dk = pbkdf1(mdSpec, password, salt, iter);

			// 생성된 추출키(DK)에서 처음 16바이트를 암호화 키(K)로 정의한다.
			byte[] key = subarray(dk, 0, keyLen);
			printBytes("key", key);

			// 추출키(DK)에서 암호화 키(K)를 제외한 나머지 4바이트를 SHA-1
			// 으로 해쉬하여 20바이트의 값(DIV)을 생성하고, 그 중 처음 16바이트를 초기
			// 벡터(IV)로 정의한다.
			
			byte[] tempBytes = subarray(dk, keyLen, dk.length);
			printBytes("tempBytes", tempBytes);
			byte[] div = hash(mdSpec, tempBytes);
			byte[] iv = subarray(div, 0, ivLen);
			printBytes("iv", iv);
			
			return new byte[][] { key, iv };
		}
	};
	
	public static PbeKeyDeriver PKCS5 = new PbeKeyDeriver() {
		
		@Override
		public byte[][] _derive(MDSpec mdSpec, String password, byte[] salt, int iter, int keyLen, int ivLen) throws Exception {
			// 추출키(DK) 생성
			byte[] dk = pbkdf1(mdSpec, password, salt, iter);

			// 생성된 추출키(DK)에서 처음 16바이트를 암호화 키(K)로 정의한다.
			byte[] key = subarray(dk, 0, keyLen);
			printBytes("key", key);

			// 16 번째 앞 길이를 잘라낸다.

			byte[] iv = subarray(dk, 16 - ivLen, 16);
			printBytes("iv", iv);
			
			return new byte[][] { key, iv };
		}
	};
}