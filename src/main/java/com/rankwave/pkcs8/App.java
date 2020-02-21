package com.rankwave.pkcs8;

import static com.rankwave.pkcs8.CryptUtil.printBytes;
import static com.rankwave.pkcs8.CryptUtil.showObject;
import static com.rankwave.pkcs8.CryptUtil.showSequence;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.nio.charset.Charset;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
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

	static final BouncyCastleProvider BC_PROV = new BouncyCastleProvider();

	static final String PBEWithSHA1AndSEED = "1.2.410.200004.1.15";
	static final String PBEWithSHA1AndDESede = "PBEWithSHA1AndDESede";
	static final String PBEWithMD5AndDES = "PBEWithMD5AndDES";
	static final Set<String> MANUAL_DECRYPTABLE_PBE_SET = new HashSet<>(Arrays.asList(PBEWithSHA1AndSEED, PBEWithSHA1AndDESede, PBEWithMD5AndDES));
	
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

		if ( MANUAL_DECRYPTABLE_PBE_SET.contains(ePKInfo.getAlgName()) ) {

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

				String cipherAlg = null;
				String keyAlg = null;
				String prov = null;
				PbeKeyDeriver deriver = null;
				MDSpec mdSpec = null;
				int keyLen = 0;
				int ivLen = 0;
				
				if ( PBEWithSHA1AndSEED.equals(ePKInfo.getAlgName()) ) {
					
					deriver = PbeKeyDeriver.SEED;
					mdSpec = MDSpec.SHA1;
					keyLen = 16;
					ivLen = 16;
					cipherAlg = "SEED/CBC/PKCS5Padding";
					keyAlg = "SEED";
					prov = "BC";
					
				} else if ( PBEWithSHA1AndDESede.equals(ePKInfo.getAlgName()) ) {
					
					deriver = PbeKeyDeriver.PKCS12;
					mdSpec = MDSpec.SHA1;
					keyLen = 24;
					ivLen = 8;
					cipherAlg = "TripleDES/CBC/PKCS5Padding";
					keyAlg = "TripleDES";
					prov = "SunJCE";
					
				} else if ( PBEWithMD5AndDES.equals(ePKInfo.getAlgName()) ) {
					
					deriver = PbeKeyDeriver.PKCS5;
					mdSpec = MDSpec.MD5;
					keyLen = 8;
					ivLen = 8;
					cipherAlg = "DES/CBC/PKCS5Padding";
					keyAlg = "DES";
					prov = "SunJCE";
				}
				
				byte[][] keyIv = deriver.derive(mdSpec, password, salt, iter, keyLen, ivLen);
				byte[] key = keyIv[0];
				printBytes("key", key);
				byte[] iv = keyIv[1];
				printBytes("iv", iv);

				Cipher cipher = Cipher.getInstance(cipherAlg, prov);
				showObject("cipher", cipher);

				cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, keyAlg), new IvParameterSpec(iv));
				
				boolean decryptManual = true;
				byte[] plain = null;
				
				if ( decryptManual ) {
					
					plain = cipher.doFinal(ePKInfo.getEncryptedData());
					printBytes("decryptedKey", plain);
					PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(plain);
					KeyFactory kf = KeyFactory.getInstance("RSA");
					privateKey = kf.generatePrivate(pkcs8Spec);
					
				}
				else {
					
					PKCS8EncodedKeySpec pkcs8Sepc = ePKInfo.getKeySpec(cipher);
					KeyFactory kf = KeyFactory.getInstance("RSA", prov);
					privateKey = kf.generatePrivate(pkcs8Sepc);
					plain = privateKey.getEncoded();
					printBytes("decryptedKey", plain);
				}
				
				//printBytes("decryptedKey", plain);
				
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

	public void run(String[] args) throws Exception {
		for ( int i = 0 ; i < args.length ; i += 2 ) {
			File file = new File(args[i]);
			String password = args[i+1];
			readKey(file, password);
		}
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

	@SuppressWarnings("unused")
	private void showCharsets() {
		Charset.availableCharsets().forEach((name, charset) -> {
			System.out.format("%s %s\n", charset.displayName(), charset.aliases());
		});
	}

	public static void main(String[] args) throws Exception {
		if ( args.length < 2 || args.length % 2 != 0 ) {
			System.err.format("java %s <PKCS#8 private key file> <password> [ <PKCS#8 private key file> <password> ... ]\n", App.class.getName());
			return;
		}
		
		Security.addProvider(BC_PROV);
		new App().run(args);
		log.debug("OK");
	}
}
