package com.rankwave.pkcs8;

import static java.lang.System.arraycopy;
import static org.apache.commons.lang3.ArrayUtils.subarray;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.EncryptedPrivateKeyInfo;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DLSequence;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CryptUtil {

	public static byte[] hash(MDSpec mdSpec, byte[]... params) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance(mdSpec.name());
		for (byte[] param : params)
			md.update(param);
		return md.digest();
	}

	public static byte[] hashIter(MDSpec mdSpec, byte[] input, int iter) throws NoSuchAlgorithmException {
		for (int i = 0; i < iter; i++)
			input = hash(mdSpec, input);
		return input;
	}

	public static byte[] fillRound(byte[] src, byte[] dst, int dstOffset, int length) {
		for (int i = 0; i < length; i++) {
			dst[dstOffset + i] = src[i % src.length];
		}
		return dst;
	}

	public static byte[] fillRound(byte[] src, byte[] dst) {
		return fillRound(src, dst, 0, dst.length);
	}

	public static byte[] fill(byte[] dst, int fromIndex, int toIndex, byte value) {
		Arrays.fill(dst, fromIndex, toIndex, value);
		return dst;
	}

	public static byte[] fill(byte[] dst, byte value) {
		return fill(dst, 0, dst.length, value);
	}

	public static int fitBlock(int length, int blockLen) {
		return blockLen * ((length + blockLen - 1) / blockLen);
	}
	
	public static void printBytes(String name, byte[] raw) {
		System.out.format("*** %s (%d) ***\n", name, raw.length);
		for (int i = 0; i < raw.length; i++) {
			System.out.format("%02x ", raw[i]);
			if ((i + 1) % 32 == 0)
				System.out.println();
		}
		System.out.println();
	}
	
	public static void showKey(File file, String password) throws Exception {
		byte[] pkbuf = FileUtils.readFileToByteArray(file);

		byte[] encryptedData = null;
		EncryptedPrivateKeyInfo ePKInfo = new EncryptedPrivateKeyInfo(pkbuf);
		printBytes("encoded", ePKInfo.getEncoded());
		printBytes("encryptedData", encryptedData = ePKInfo.getEncryptedData());

		File newFile = new File(file.getAbsolutePath().replaceAll("\\.[^\\./]+$", ".bin"));
		log.debug("newFile: {}", newFile);
		FileUtils.writeByteArrayToFile(newFile, encryptedData);
	}

	public static void showObject(String type, Object obj) {
		log.debug("{}: {}: {}", type, obj != null ? obj.getClass() : "null", obj);
	}

	public static void showSequence(String type, DLSequence seq) {
		for (int i = 0; i < seq.size(); i++) {
			ASN1Encodable obj = seq.getObjectAt(i);
			showObject(String.format("%s[%d]", type, i), obj);
		}
	}

	public static byte[] pbkdf1(MDSpec mdSpec, String password, byte[] salt, int iter) throws NoSuchAlgorithmException {
		byte[] dk = hash(mdSpec, password.getBytes(), salt);
		return hashIter(mdSpec, dk, iter-1);
	}
	
	public static byte[] derivePKCS12Key(MDSpec mdSpec, String password, byte[] salt, int id, int iter, int needLen)
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
			BigInteger blockFilledHashPlusOne = new BigInteger(fillRound(Ai, new byte[blockLen])).add(new BigInteger("1"));

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
		}

		return out.toByteArray();
	}
}
