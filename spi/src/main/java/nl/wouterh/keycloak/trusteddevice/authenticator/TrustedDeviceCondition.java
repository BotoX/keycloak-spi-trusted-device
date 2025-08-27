package nl.wouterh.keycloak.trusteddevice.authenticator;

import lombok.extern.jbosslog.JBossLog;
import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialModel;
import nl.wouterh.keycloak.trusteddevice.util.TrustedDeviceToken;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

@JBossLog
public class TrustedDeviceCondition implements ConditionalAuthenticator {

  public static final TrustedDeviceCondition SINGLETON = new TrustedDeviceCondition();

  @Override
  public boolean matchCondition(AuthenticationFlowContext context) {
    AuthenticatorConfigModel authConfig = context.getAuthenticatorConfig();

    TrustedDeviceCredentialModel credential = TrustedDeviceToken.getCredentialFromCookie(
        context.getSession(), context.getRealm(), context.getUser());

    boolean trustedDevice = credential != null;

    boolean negateOutput;
    if (authConfig != null && authConfig.getConfig() != null) {
      negateOutput = Boolean.parseBoolean(
          authConfig.getConfig().getOrDefault(TrustedDeviceConditionFactory.CONF_NEGATE, "true"));
    } else {
        negateOutput = true; // Negate output by default
    }

    return negateOutput != trustedDevice;
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    // Not used
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    // Not used
  }

  @Override
  public void close() {
    // Does nothing
  }
}
