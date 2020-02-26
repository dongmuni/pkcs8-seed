package com.rankwave.pkcs8;

import static com.rankwave.pkcs8.CryptUtil.showObject;

import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JsonWebTokenTest {
	
	@SuppressWarnings("unchecked")
	public static <K, V> Map<K, V> toMap(Object ... args) {
		Map<K, V> map = new LinkedHashMap<>();
		for ( int i = 0 ; i < args.length ; i += 2 ) {
			K k = (K)args[i];
			V v = (V)args[i+1];
			map.put(k, v);
		}
		return map;
	}
	
	public static final byte[] SECRET = secret(); 
	
	public static byte[] secret() {
		try {
			return Hex.decodeHex("368e91f9e4a8802f687c34b1068c8ea2be61d12902ecd5c54c0f928c9171ec28");
		} catch (DecoderException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static String createJwt(String issuer, long expMs) {
		Map<String, Object> headers = toMap(
				"alg", "HS256",
				"typ", "JWT"
		);
		
		String jwt = Jwts.builder()
				.setHeader(headers)
				.setIssuer(issuer)
				.setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis() + expMs))
				.signWith(SignatureAlgorithm.HS256, SECRET)
				.compact();
		
		return jwt;
	}
	
	public static void parseJwt(String jwt) {
		Claims payload2 = Jwts.parser()
				.setSigningKey(SECRET)
				.parseClaimsJws(jwt)
				.getBody();
		showObject("payload2", payload2);
		
		Date exp = payload2.getExpiration();
		showObject("exp", exp);
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException {
		String jwt = createJwt("dmp-admin", 60000L);
		showObject("jwt", jwt);
		parseJwt(jwt);
		
		String[] arr = jwt.split("\\.");
		
		String header = new String(Base64.decodeBase64(arr[0]));
		String payload = new String(Base64.decodeBase64(arr[1]));
		String signature = arr[2];
		
		System.out.format("HEADER:    %s\n", header);
		System.out.format("PAYLOAD:   %s\n", payload);
		System.out.format("SIGNAGURE: %s\n", signature);
	}
}
