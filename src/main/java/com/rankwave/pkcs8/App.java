package com.rankwave.pkcs8;

import static java.lang.System.arraycopy;
import static org.apache.commons.lang3.ArrayUtils.subarray;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import lombok.extern.slf4j.Slf4j;

/**
 * Hello world!
 *
 */
@Slf4j
public class App {
	private void printBytes(String name, byte[] raw) {
		System.out.format("*** %s (%d) ***\n", name, raw.length);
		for (int i = 0; i < raw.length; i++) {
			System.out.format("%02x ", raw[i]);
			if ((i + 1) % 32 == 0)
				System.out.println();
		}
		System.out.println();
	}

	public void showKey(File file, String password) throws Exception {
		byte[] pkbuf = FileUtils.readFileToByteArray(file);

		byte[] encryptedData = null;
		EncryptedPrivateKeyInfo ePKInfo = new EncryptedPrivateKeyInfo(pkbuf);
		printBytes("encoded", ePKInfo.getEncoded());
		printBytes("encryptedData", encryptedData = ePKInfo.getEncryptedData());

		File newFile = new File(file.getAbsolutePath().replaceAll("\\.[^\\./]+$", ".bin"));
		log.debug("newFile: {}", newFile);
		FileUtils.writeByteArrayToFile(newFile, encryptedData);
	}

	public void showObject(String type, Object obj) {
		log.debug("{}: {}: {}", type, obj != null ? obj.getClass() : "null", obj);
	}

	public void showSequence(String type, DLSequence seq) {
		for (int i = 0; i < seq.size(); i++) {
			ASN1Encodable obj = seq.getObjectAt(i);
			showObject(String.format("%s[%d]", type, i), obj);
		}
	}

	public void readKey(File file, String password) throws Exception {
		PrivateKey privateKey = null;
		byte[] pkbuf = FileUtils.readFileToByteArray(file);

		EncryptedPrivateKeyInfo ePKInfo = new EncryptedPrivateKeyInfo(pkbuf);
		log.debug("Algorithm Name: {}", ePKInfo.getAlgName());
		printBytes("encoded", ePKInfo.getEncoded());
		printBytes("encryptedData", ePKInfo.getEncryptedData());

		AlgorithmParameters algParams = ePKInfo.getAlgParameters();
		log.debug("AlgorithmParameters: value: {}", algParams);
		log.debug("AlgorithmParameters: class: {}", algParams != null ? algParams.getClass() : "null");

		if ("1.2.410.200004.1.15".equals(ePKInfo.getAlgName())) {

			try (ASN1InputStream is = new ASN1InputStream(new ByteArrayInputStream(pkbuf));) {
				ASN1Primitive obj = is.readObject();
				showObject("ASN1Primitive", obj);

				DLSequence seq1 = (DLSequence) obj;
				showSequence("seq1", seq1);

				DLSequence seq2 = (DLSequence) seq1.getObjectAt(0);
				showSequence("seq2", seq2);

				DEROctetString octet1 = (DEROctetString) seq1.getObjectAt(1);
				showObject("octet1", octet1);

				ASN1ObjectIdentifier oid1 = (ASN1ObjectIdentifier) seq2.getObjectAt(0);
				showObject("oid1", oid1);

				DLSequence seq3 = (DLSequence) seq2.getObjectAt(1);
				showSequence("seq3", seq3);

				DEROctetString octet2 = (DEROctetString) seq3.getObjectAt(0);
				showObject("octet2", octet2);

				ASN1Integer integer = (ASN1Integer) seq3.getObjectAt(1);
				showObject("integer", integer);

				byte[] salt = octet2.getOctets();
				log.debug("salt: {}", Hex.encodeHexString(salt));

				int iter = integer.getValue().intValue();
				log.debug("iter: {}", iter);

				boolean useMy = false;
				byte[][] keyIv = null;
				byte[] key = null, iv = null; 
				
				if ( useMy ) {
					keyIv = deriveSha1TripleDesKeyIv(password, salt, iter);
				} else {
					keyIv = this.deriveSEEDKeyIv(password, salt, iter);
				}
				
				key = keyIv[0];
				printBytes("key", key);
				
				iv = keyIv[1];
				printBytes("iv", iv);

				Cipher cipher = Cipher.getInstance("SEED/CBC/PKCS5Padding", BC_PROV);
				showObject("cipher", cipher);

				cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "SEED"), new IvParameterSpec(iv));
				
				boolean decryptManual = true;
				byte[] plain = null;
				
				if ( decryptManual ) {
					
					plain = cipher.doFinal(ePKInfo.getEncryptedData());
					PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(plain);
					KeyFactory kf = KeyFactory.getInstance("RSA");
					privateKey = kf.generatePrivate(pkcs8Spec);
					
				}
				else {
					
					PKCS8EncodedKeySpec pkcs8Sepc = ePKInfo.getKeySpec(cipher);
					KeyFactory kf = KeyFactory.getInstance("RSA", BC_PROV);
					privateKey = kf.generatePrivate(pkcs8Sepc);
					plain = privateKey.getEncoded();
				}
				
				printBytes("decryptedKey", plain);
				
				File newFile = new File(file.getAbsolutePath() + "_");
				FileUtils.writeByteArrayToFile(newFile, plain);
				log.debug("write file {}", newFile);
			}

		} else {

			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());

			SecretKeyFactory skFac = SecretKeyFactory.getInstance(ePKInfo.getAlgName());
			log.debug("SecretKeyFactory: {} {}", skFac);

			Key pbeKey = skFac.generateSecret(pbeKeySpec);

			Cipher cipher = Cipher.getInstance(ePKInfo.getAlgName());
			log.debug("Cipher Algorithm: {}", ePKInfo.getAlgName());

			cipher.init(Cipher.DECRYPT_MODE, pbeKey, algParams);
			KeySpec pkcs8KeySpec = ePKInfo.getKeySpec(cipher);
			KeyFactory rsaKeyFac = KeyFactory.getInstance("RSA");

			privateKey = (RSAPrivateCrtKey) rsaKeyFac.generatePrivate(pkcs8KeySpec);
		}
		
		showObject("Private Key", privateKey);
	}

	public void run() throws Exception {
		File file = new File("data/signPri.key");
		String password = "***********";
		readKey(file, password);
	}

	public void listProvs() throws FileNotFoundException {

		try (PrintStream out = new PrintStream(new FileOutputStream("providers.log"));) {
			for (Provider prov : Security.getProviders()) {
				out.format("--------------------------------------------- PROV: %s\n", prov.getName());
				prov.keySet().forEach(key -> {
					String value = prov.getProperty((String) key);
					out.format("%s: %s - %s\n", prov.getName(), key, value);
				});
			}
		}
	}

	public static enum MDSpec {
		MD5(512, 128), SHA0(512, 160), SHA1(512, 160), SHA224(512, 224), SHA256(512, 256), SHA384(1024, 384),
		SHA512(1024, 512), SHA512_224(1024, 224), SHA512_256(1024, 256), SHA3_224(1152, 224), SHA3_256(1088, 256),
		SHA3_384(832, 384), SHA3_512(576, 512), SHAKE128(1344, 0), SHAKE256(1088, 0);

		int blockSize;
		int outputSize;

		MDSpec(int blockSize, int outputSize) {
			this.blockSize = blockSize;
			this.outputSize = outputSize;
		}

		public int getBlockSizeInBits() {
			return blockSize;
		}

		public int getBlockSizeInBytes() {
			return blockSize / 8;
		}

		public int getOutputSizeInBits() {
			return outputSize;
		}

		public int getOutputSizeInBytes() {
			return outputSize / 8;
		}
	}

	public byte[] hash(MDSpec mdSpec, byte[]... params) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance(mdSpec.name());
		for (byte[] param : params)
			md.update(param);
		return md.digest();
	}

	public byte[] hashIter(MDSpec mdSpec, byte[] input, int iter) throws NoSuchAlgorithmException {
		for (int i = 0; i < iter; i++)
			input = hash(mdSpec, input);
		return input;
	}

	public byte[] fillRound(byte[] src, byte[] dst, int dstOffset, int length) {
		for (int i = 0; i < length; i++) {
			dst[dstOffset + i] = src[i % src.length];
		}
		return dst;
	}

	public byte[] fillRound(byte[] src, byte[] dst) {
		return fillRound(src, dst, 0, dst.length);
	}

	public byte[] fill(byte[] dst, int fromIndex, int toIndex, byte value) {
		Arrays.fill(dst, fromIndex, toIndex, value);
		return dst;
	}

	public byte[] fill(byte[] dst, byte value) {
		return fill(dst, 0, dst.length, value);
	}

	public int fitBlock(int length, int blockLen) {
		return blockLen * ((length + blockLen - 1) / blockLen);
	}

	static final BigInteger ONE = new BigInteger("1");

	/**
	 * @param password
	 * @param salt
	 * @param id
	 * @param iter
	 * @param needLen
	 * @param mdSpec
	 * @return
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchAlgorithmException
	 */
	public byte[] derivePKCS12Key(String password, byte[] salt, int id, int iter, int needLen, MDSpec mdSpec)
			throws UnsupportedEncodingException, NoSuchAlgorithmException {
		byte[] pass = password.getBytes("UTF-16BE");
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int blockLen = mdSpec.getBlockSizeInBytes();
		int hashLen = mdSpec.getOutputSizeInBytes();
		int Slen = fitBlock(salt.length, blockLen);
		int Plen = fitBlock(pass.length, blockLen);
		byte[] D = fill(new byte[blockLen], (byte) id);
		byte[] I = new byte[Slen + Plen];
		fillRound(salt, I, 0, Slen);
		fillRound(pass, I, Slen, Plen);
		int remainLen = needLen;

		for (;;) {

			byte[] Ai = hash(mdSpec, D, I);

			Ai = hashIter(mdSpec, Ai, iter - 1);

			out.write(Ai, 0, Math.min(remainLen, hashLen));

			if (hashLen >= remainLen)
				break;

			remainLen -= hashLen;

			// In case of SHA-1: Fill block (64 bytes) with hash (20 bytes)
			BigInteger blockFilledHashPlusOne = new BigInteger(fillRound(Ai, new byte[blockLen])).add(ONE);

			for (int blockOffset = 0; blockOffset < I.length; blockOffset += blockLen) {

				byte[] B = new BigInteger(subarray(I, blockOffset, blockOffset + blockLen)).add(blockFilledHashPlusOne)
						.toByteArray();

				// If more than 2^(v*8) - 1 cut off MSB
				if (B.length > blockLen) {

					arraycopy(B, B.length - blockLen, I, blockOffset, blockLen);

					// If less than v bytes pad with zeroes
				} else if (B.length < blockLen) {

					fill(I, blockOffset, blockOffset + blockLen - B.length, (byte) 0);
					arraycopy(B, 0, I, blockOffset + blockLen - B.length, B.length);

				} else {

					arraycopy(B, 0, I, blockOffset, B.length);
				}
			}

			break;
		}

		return out.toByteArray();
	}

	@SuppressWarnings("unused")
	private void showCharsets() {
		Charset.availableCharsets().forEach((name, charset) -> {
			System.out.format("%s %s\n", charset.displayName(), charset.aliases());
		});
	}

	static final BouncyCastleProvider BC_PROV = new BouncyCastleProvider();

	public byte[] pbkdf1(String password, byte[] salt, int iter) throws NoSuchAlgorithmException {
		byte[] dk = hash(MDSpec.SHA1, password.getBytes(), salt);
		return hashIter(MDSpec.SHA1, dk, iter-1);
	}
	
	public byte[][] deriveSha1TripleDesKeyIv(String password, byte[] salt, int iter) throws UnsupportedEncodingException, NoSuchAlgorithmException {
		String pass = password + '\0';
		
		byte[] key = derivePKCS12Key(pass, salt, 1, iter, 16, MDSpec.SHA1);
		printBytes("key", key);

		byte[] iv = derivePKCS12Key(pass, salt, 2, iter, 16, MDSpec.SHA1);
		printBytes("iv", iv);
		
		return new byte[][] { key, iv };
	}

	public byte[][] deriveSEEDKeyIv(String password, byte[] salt, int iter) throws NoSuchAlgorithmException {
		// 추출키(DK) 생성
		byte[] dk = pbkdf1(password, salt, iter);

		// 생성된 추출키(DK)에서 처음 16바이트를 암호화 키(K)로 정의한다.
		byte[] key = subarray(dk, 0, 16);
		printBytes("key", key);

		// 추출키(DK)에서 암호화 키(K)를 제외한 나머지 4바이트를 SHA-1
		// 으로 해쉬하여 20바이트의 값(DIV)을 생성하고, 그 중 처음 16바이트를 초기
		// 벡터(IV)로 정의한다.
		
		byte[] tmp4Bytes = subarray(dk, 16, 40);
		byte[] div = hash(MDSpec.SHA1, tmp4Bytes);
		byte[] iv = subarray(div, 0, 16);
		printBytes("iv", iv);
		
		return new byte[][] { key, iv };
	}

	public static void main(String[] args) throws Exception {
		Security.addProvider(BC_PROV);

		new App().run();

		log.debug("OK");
	}
}
