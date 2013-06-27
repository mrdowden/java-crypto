package org.tekyn.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;

import org.junit.Test;

public class PBKDF2TestStatic {

	@Test
	public void intMatchesPublicAlgorithm( ) {
		assertArrayEquals(INT(1234125), PBKDF2.INT(1234125));
	}

	@Test
	public void intZeroNotAffectedByByteOrder( ) {
		byte[] expected = new byte[] { 0, 0, 0, 0 };
		assertArrayEquals(expected, PBKDF2.INT(0));
	}

	@Test
	public void intOfIntegerMaxValue( ) {
		byte[] expected = new byte[] { 127, -1, -1, -1 };
		assertArrayEquals(expected, PBKDF2.INT(Integer.MAX_VALUE));
	}

	@Test
	public void intOfIntegerOne( ) {
		byte[] expected = new byte[] { 0, 0, 0, 1 };
		assertArrayEquals(expected, PBKDF2.INT(1));
	}

	@Test
	public void xorWorking( ) {
		byte[] a = new byte[] { 127, 127, 127, 0, 0, 0 };
		byte[] b = new byte[] { 1, 2, 4, 1, 2, 4 };

		PBKDF2.xor(a, b);
		assertEquals(126, a[0]);
		assertEquals(125, a[1]);
		assertEquals(123, a[2]);
		assertEquals(1, a[3]);
		assertEquals(2, a[4]);
		assertEquals(4, a[5]);
	}

	@Test
	public void xorNullOnEmptyArray( ) {
		byte[] a = new byte[0];
		byte[] b = new byte[0];
		PBKDF2.xor(a, null);
		assertEquals(a, a);
		assertSame(a, a);
		assertNotSame(b, a);
	}

	@Test( expected = NullPointerException.class )
	public void xorNullOnNullThrowsNPE( ) {
		PBKDF2.xor(null, null);
	}

	@Test( expected = NullPointerException.class )
	public void xorNullOnNonEmptyArrayThrowsNPE( ) {
		byte[] a = new byte[] { 127, 127, 127, 0, 0, 0 };
		PBKDF2.xor(a, null);
	}

	@Test( expected = NullPointerException.class )
	public void xorNonEmptyArrayOnNullThrowsNPE( ) {
		byte[] a = new byte[] { 127, 127, 127, 0, 0, 0 };
		PBKDF2.xor(null, a);
	}

	@Test( expected = ArrayIndexOutOfBoundsException.class )
	public void xorEmptyArrayOnNonEmptyArrayThrowsIOB( ) {
		byte[] a = new byte[] { 127, 127, 127, 0, 0, 0 };
		PBKDF2.xor(a, new byte[0]);
	}

	/**
	 * Uses an inelegant but publicly verifiable routine to convert an integer
	 * to its representative bytes.
	 */
	static byte[] INT( int i ) {
		final byte[] dest = new byte[4];
		dest[0] = (byte) ( i / ( 256 * 256 * 256 ) );
		dest[1] = (byte) ( i / ( 256 * 256 ) );
		dest[2] = (byte) ( i / ( 256 ) );
		dest[3] = (byte) ( i );
		return dest;
	}

}
