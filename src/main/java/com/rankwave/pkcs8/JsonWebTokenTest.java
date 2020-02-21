package com.rankwave.pkcs8;

import static com.rankwave.pkcs8.CryptUtil.showObject;

import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JsonWebTokenTest {
	
	@SuppressWarnings("unchecked")
	public static <K, V> Map<K, V> toMap(Object ... args) {
		Map<K, V> map = new HashMap<>();
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
			return Hex.decodeHex("29655d56e8c0050781ed55ede0383e2409dee8b476b0c19c80b54d36109a57d5");
		} catch (DecoderException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static String createJwt(String userid, long expMs) {
		Map<String, Object> headers = toMap(
				"typ", "JWT", 
				"alg", "HS256"
		);
		
		Map<String, Object> payloads = toMap(
				"userid", userid
		);
		
		String jwt = Jwts.builder()
				.setHeader(headers)
				.setClaims(payloads)
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
		String jwt = createJwt("dmlim@nate.com", 10000L);
		showObject("jwt", jwt);
		parseJwt(jwt);
	}
}
