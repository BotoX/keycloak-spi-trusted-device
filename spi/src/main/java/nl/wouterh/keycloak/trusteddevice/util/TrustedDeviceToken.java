package nl.wouterh.keycloak.trusteddevice.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.NewCookie.SameSite;
import jakarta.ws.rs.core.Cookie;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialModel;
import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialProvider;
import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialProviderFactory;
import org.keycloak.TokenCategory;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;

@Getter
@Setter
@NoArgsConstructor
public class TrustedDeviceToken extends JsonWebToken {

  /**
   * Name of the single, shared cookie used by earlier versions. It can only hold the token of one
   * user, so it is no longer written. It is still read to stay compatible with devices that were
   * trusted before per-user cookies were introduced.
   */
  public static final String COOKIE_NAME = "KEYCLOAK_TRUSTED_DEVICE";

  private static final String COOKIE_PREFIX = COOKIE_NAME + "_";

  /**
   * Cookie name for the given user: {@code KEYCLOAK_TRUSTED_DEVICE_<hash of user id>}. A hash is
   * used because user ids (e.g. of federated users) may contain characters that are not valid in
   * cookie names. The cookie path is already scoped to the realm.
   */
  public static String getCookieName(UserModel user) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256")
          .digest(user.getId().getBytes(StandardCharsets.UTF_8));
      return COOKIE_PREFIX + HexFormat.of().formatHex(digest, 0, 16);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  public static void addCookie(KeycloakSession session, RealmModel realm, UserModel user,
      TrustedDeviceToken value, int maxAge) {
    addCookie(session, realm, getCookieName(user), session.tokens().encode(value), maxAge);
  }

  private static void addCookie(KeycloakSession session, RealmModel realm, String name,
      String value, int maxAge) {
    UriBuilder baseUriBuilder = session.getContext().getUri().getBaseUriBuilder();
    String path = baseUriBuilder.path("realms").path(realm.getName()).path("/").build().getPath();

    ClientConnection connection = session.getContext().getConnection();
    boolean secure = realm.getSslRequired().isRequired(connection);
    SameSite sameSiteValue = secure ? SameSite.NONE : null;
    NewCookie newCookie = new NewCookie.Builder(name)
      .maxAge(maxAge)
      .value(value)
      .path(path)
      .secure(secure)
      .httpOnly(true)
      .sameSite(sameSiteValue)
      .build();

    session.getContext().getHttpResponse().setCookieIfAbsent(newCookie);
  }

  private static TrustedDeviceToken getCookie(KeycloakSession session, String name) {
    Cookie cookie = session.getContext().getRequestHeaders().getCookies().get(name);
    long time = Time.currentTime();

    if (cookie == null) {
      return null;
    }

    TrustedDeviceToken decoded = session.tokens().decode(cookie.getValue(), TrustedDeviceToken.class);
    if (decoded != null && (decoded.getExp() == null || decoded.getExp() > time)) {
      return decoded;
    }

    return null;
  }

  private static TrustedDeviceCredentialModel resolveCredential(KeycloakSession session,
      RealmModel realm, UserModel user, TrustedDeviceToken deviceToken) {
    if (deviceToken == null || deviceToken.getId() == null || deviceToken.getSecret() == null) {
      return null;
    }

    TrustedDeviceCredentialProvider trustedDeviceCredentialProvider = (TrustedDeviceCredentialProvider) session
        .getProvider(CredentialProvider.class, TrustedDeviceCredentialProviderFactory.PROVIDER_ID);

    TrustedDeviceCredentialModel credential = trustedDeviceCredentialProvider.getActiveCredentialById(
        realm, user, deviceToken.getId());
    if (credential == null || !deviceToken.getSecret().equals(credential.getDeviceId())) {
      return null;
    }

    return credential;
  }

  public static TrustedDeviceCredentialModel getCredentialFromCookie(KeycloakSession session,
      RealmModel realm, UserModel user) {
    // 1. Per-user cookie
    TrustedDeviceCredentialModel credential = resolveCredential(session, realm, user,
        getCookie(session, getCookieName(user)));
    if (credential != null) {
      return credential;
    }

    // 2. Legacy shared cookie. It may belong to another account, in which case the lookup above
    // fails for this user and the cookie is left untouched.
    TrustedDeviceToken legacyToken = getCookie(session, COOKIE_NAME);
    credential = resolveCredential(session, realm, user, legacyToken);
    if (credential != null) {
      migrateLegacyCookie(session, realm, user, legacyToken);
    }

    return credential;
  }

  /**
   * Move a legacy cookie that is valid for this user to the per-user cookie, and remove the legacy
   * cookie so it no longer occupies the shared slot.
   */
  private static void migrateLegacyCookie(KeycloakSession session, RealmModel realm,
      UserModel user, TrustedDeviceToken legacyToken) {
    int maxAge = Integer.MAX_VALUE;
    if (legacyToken.getExp() != null) {
      maxAge = (int) Math.max(1, Math.min(Integer.MAX_VALUE, legacyToken.getExp() - Time.currentTime()));
    }

    TrustedDeviceToken migrated = new TrustedDeviceToken(legacyToken.getId(),
        legacyToken.getSecret(), legacyToken.getExp());
    addCookie(session, realm, user, migrated, maxAge);
    addCookie(session, realm, COOKIE_NAME, "", 0);
  }

  public TrustedDeviceToken(String id, String secret, Long exp) {
    this.id = id;
    this.secret = secret;
    iat((long) Time.currentTime());
    exp(exp);
  }

  @Override
  public TokenCategory getCategory() {
    return TokenCategory.INTERNAL;
  }

  private String id;

  private String secret;
}
