/**
 * Java implementation of RFC 5297 SIV Authenticated Encryption.
 * <p>
 * Two usage patterns are supported:
 * <ul>
 *   <li>Direct API: Use {@link org.cryptomator.siv.SivEngine} for encrypt/decrypt operations</li>
 *   <li>JCE Provider: Register {@link org.cryptomator.siv.SivProvider} and use standard JCE APIs</li>
 * </ul>
 *
 * @see <a href="https://tools.ietf.org/html/rfc5297">RFC 5297</a>
 */
package org.cryptomator.siv;