/**
 * Java implementation of RFC 5297 SIV Authenticated Encryption.
 * <p>
 * Use an instance of the {@link org.cryptomator.siv.SivMode} class to
 * {@link org.cryptomator.siv.SivMode#encrypt(javax.crypto.SecretKey, javax.crypto.SecretKey, byte[], byte[]...) encrypt} or
 * {@link org.cryptomator.siv.SivMode#decrypt(javax.crypto.SecretKey, javax.crypto.SecretKey, byte[], byte[]...) decrypt} data.
 */
package org.cryptomator.siv;