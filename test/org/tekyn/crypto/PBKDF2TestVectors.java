package org.tekyn.crypto;

import static java.util.Arrays.asList;
import static javax.xml.bind.DatatypeConverter.parseHexBinary;
import static org.junit.Assert.assertArrayEquals;

import java.security.spec.KeySpec;
import java.util.Collection;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class PBKDF2TestVectors {

	String expectedDK;
	String password;
	String salt;
	int iterations;
	int keyLen;
	
	public PBKDF2TestVectors(String expectedDK, String P, String S, int c, int dkLen) {
		this.expectedDK = expectedDK;
		this.password = P;
		this.salt = S;
		this.iterations = c;
		this.keyLen = dkLen;
	}
	
	/**
	 * Returns the official PBKDF2WithHmacSHA1 test vectors/
	 * 
	 * @see <a href="http://tools.ietf.org/html/rfc6070">RFC 6070</a>
	 */
	@Parameters
	public static Collection<Object[]> listTestVectors() {
		return asList(
				new Object[] { "0c60c80f961f0e71f3a9b524af6012062fe037a6", "password", "salt", 1, 20 },
				new Object[] { "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957", "password", "salt", 2, 20 },
				new Object[] { "4b007901b765489abead49d926f721d065a429c1", "password", "salt", 4096, 20 },
				new Object[] { "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984", "password", "salt", 16777216, 20 },
				new Object[] { "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038", "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25 },
				new Object[] { "56fa6aa75548099dcc37d7f03425e0c3", "pass\0word", "sa\0lt", 4096, 16 }
				);
	}

	@Test
	public void validateTestVectors( ) throws Exception {
		PBKDF2 subject = new PBKDF2("HmacSHA1", "UTF-8");
		// Verify official Test Vectors
		assertArrayEquals(
				parseHexBinary(expectedDK),
				subject.deriveKey(password.toCharArray(),
						salt.getBytes("UTF-8"), iterations, keyLen));
	}

	@Test
	public void validateAgainstNative( ) throws Exception {
		PBKDF2 subject = new PBKDF2("HmacSHA1", "UTF-8");
		// Verify Native Derive Key works as Expected
		assertArrayEquals(
				nativeDeriveKey(
						password, salt.getBytes("UTF-8"), iterations, keyLen),
				subject.deriveKey(password.toCharArray(),
						salt.getBytes("UTF-8"), iterations, keyLen));
	}

	/**
	 * Uses the Java native {@code PBKDF2WithHmacSHA1} implementation to derive
	 * a key for the given parameters.
	 */
	static byte[] nativeDeriveKey( String strPassword, byte[] salt,
			int nIterations, int nKeyLen ) {
		byte[] baDerived = null;

		try {
			SecretKeyFactory f = SecretKeyFactory
					.getInstance("PBKDF2WithHmacSHA1");
			KeySpec ks = new PBEKeySpec(strPassword.toCharArray(),
					salt, nIterations, nKeyLen * 8);
			SecretKey s = f.generateSecret(ks);
			baDerived = s.getEncoded();
		}
		catch ( Exception e ) {
			e.printStackTrace();
		}

		return baDerived;
	}

}
