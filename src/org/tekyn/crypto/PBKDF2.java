/**
 * Copyright 2013 Technology Innovations, LLC. "Tekyn"
 * 
 * This file is part of the Tekyn java-crypto library.
 *
 * Java-crypto is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Java-crypto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with java-crypto.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.tekyn.crypto;

import static java.lang.Math.ceil;
import static java.lang.Math.pow;
import static java.lang.System.arraycopy;
import static java.nio.charset.Charset.defaultCharset;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Implementation of the PBKDF2 (Password-Based Key Derivation Function 2)
 * documented in RFC 2898.
 * 
 * @author Michael Dowden, michael@tekyn.com
 * @see <a href="http://tools.ietf.org/html/rfc2898">RFC 2898</a>
 */
public final class PBKDF2 {

	private final String	algorithm;
	private final Charset	charset;
	private final Mac		prf;

	/**
	 * Constructs function based upon the given MAC algorithm, using the default
	 * Charset to encode the password.
	 * 
	 * @param algorithm
	 *            the standard name of the requested MAC algorithm
	 * @throws NoSuchAlgorithmException
	 *             if no Provider supports a MacSpi implementation for the
	 *             specified algorithm
	 * @see <a
	 *      href="http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Mac">Java
	 *      7 SE Mac Algorithms</a>
	 */
	public PBKDF2( final String algorithm ) throws NoSuchAlgorithmException {
		this(algorithm, defaultCharset());
	}

	/**
	 * Constructs function based upon the given MAC algorithm and Charset.
	 * 
	 * @param algorithm
	 *            the standard name of the requested MAC algorithm
	 * @param charsetName
	 *            The name of a supported charset for encoding the password
	 * @throws NoSuchAlgorithmException
	 *             if no Provider supports a MacSpi implementation for the
	 *             specified algorithm
	 * @see <a
	 *      href="http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Mac">Java
	 *      7 SE Mac Algorithms</a>
	 * @see <a
	 *      href="http://docs.oracle.com/javase/7/docs/api/java/nio/charset/Charset.html">Java
	 *      7 SE Charsets</a>
	 */
	public PBKDF2( final String algorithm, final String charsetName )
			throws NoSuchAlgorithmException {
		this(algorithm, Charset.forName(charsetName));
	}

	/**
	 * Constructs function based upon the given MAC algorithm and Charset.
	 * 
	 * @param algorithm
	 *            the standard name of the requested MAC algorithm
	 * @param charset
	 *            The charset to be used for encoding the password
	 * @throws NoSuchAlgorithmException
	 *             if no Provider supports a MacSpi implementation for the
	 *             specified algorithm
	 * @see <a
	 *      href="http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Mac">Java
	 *      7 SE Mac Algorithms</a>
	 * @see <a
	 *      href="http://docs.oracle.com/javase/7/docs/api/java/nio/charset/Charset.html">Java
	 *      7 SE Charsets</a>
	 */
	public PBKDF2( final String algorithm, final Charset charset )
			throws NoSuchAlgorithmException {
		this.algorithm = algorithm;
		this.charset = charset;
		this.prf = Mac.getInstance(algorithm);
	}

	/**
	 * Uses PBKDF2 and the configured MAC algorithm to derive a key from the
	 * given parameters.
	 * 
	 * @param password
	 *            the master password from which a derived key is generated
	 * @param salt
	 *            the cryptographic salt
	 * @param c
	 *            desired number of iterations
	 * @param dkLen
	 *            desired length of the derived key, in octets
	 * @return the derived key
	 * @throws InvalidKeyException
	 *             if the configured MAC algorithm cannot be initialized with
	 *             the password provided
	 */
	public byte[] deriveKey( final char[] password, final byte[] salt,
			final int c, final int dkLen ) throws InvalidKeyException {

		// Calculate parameters
		final int hLen = prf.getMacLength();
		final int l = (int) ceil((double) dkLen / (double) hLen);
		// The r variable is not needed due to implementation details
		// final int r = dkLen - ( l - 1 ) * hLen;

		if ( dkLen > ( pow(2, 32) - 1 ) * hLen ) {
			throw new IllegalArgumentException("derived key too long");
		}

		// Convert password to bytes
		final byte[] pass = charset.encode(CharBuffer.wrap(password)).array();
		// Initialize PRF with Password-based Key
		prf.init(new SecretKeySpec(pass, algorithm));

		// Calculate derivation
		final ByteBuffer T = ByteBuffer.allocate(l * hLen);
		for ( int i = 1 ; i <= l ; i++ ) {
			T.put(F(pass, salt, c, i));
		}

		// Copy derived key into an array (Works for all values of r)
		final byte[] DK = new byte[dkLen];
		arraycopy(T.array(), 0, DK, 0, dkLen);

		return DK;
	}

	/**
	 * Computes the exclusive-or sum of the pseudorandom function.
	 */
	private byte[] F( byte[] password, byte[] salt, int iterations, int i ) {
		// Setup initial salt : Salt || INT(i)
		final byte[] initialSalt = ByteBuffer.allocate(salt.length + 4)
				.put(salt).put(INT(i))
				.array();
		// U1 uses the initial salt, subsequent U use previous U
		byte[] Ux = initialSalt; // U0
		final byte[] result = new byte[prf.getMacLength()];
		// Calculate U2 - Uc, applying xor between runs
		for ( int n = 1 ; n <= iterations ; n++ ) {
			// Ux = PRF(password, Ux);
			Ux = prf.doFinal(Ux);
			xor(result, Ux);
		}
		return result;
	}

	/**
	 * Performs an XOR operation between two sets of values, placing the result
	 * into the destination array.
	 * 
	 * @param dest
	 *            the destination array, included in the xor operation
	 * @param src
	 *            the source array which gets xored onto the destination
	 */
	static void xor( byte[] dest, byte[] src ) {
		for ( int i = 0 ; i < dest.length ; i++ ) {
			dest[i] ^= src[i];
		}
	}

	/**
	 * Converts an integer value to its underlying byte array using
	 * {@link ByteOrder#BIG_ENDIAN BIG_ENDIAN} byte order.
	 * 
	 * @param value
	 *            the integer value to convert
	 * @return the byte array representation
	 */
	static byte[] INT( final int value ) {
		return ByteBuffer.allocate(4)
				.order(ByteOrder.BIG_ENDIAN)
				.putInt(value)
				.array();
	}

}
