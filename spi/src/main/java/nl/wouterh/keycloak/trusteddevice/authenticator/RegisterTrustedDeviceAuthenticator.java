package nl.wouterh.keycloak.trusteddevice.authenticator;

import static nl.wouterh.keycloak.trusteddevice.authenticator.RegisterTrustedDeviceAuthenticatorFactory.CONF_DURATION;
import static nl.wouterh.keycloak.trusteddevice.authenticator.RegisterTrustedDeviceAuthenticatorFactory.CONF_PASSKEY_BUTTON;
import static nl.wouterh.keycloak.trusteddevice.authenticator.RegisterTrustedDeviceAuthenticatorFactory.CONF_REQUIRED_ACTION;
import static nl.wouterh.keycloak.trusteddevice.authenticator.RegisterTrustedDeviceAuthenticatorFactory.PROVIDER_ID;
import static nl.wouterh.keycloak.trusteddevice.authenticator.RegisterTrustedDeviceAuthenticatorFactory.CONFIG_PROPERTIES;

import java.io.IOException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Map;
import java.util.List;

import org.apache.commons.codec.binary.Hex;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionConfigModel;
import org.keycloak.models.RequiredActionProviderModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;

import com.google.auto.service.AutoService;
import com.google.common.base.Strings;
import com.fasterxml.jackson.core.type.TypeReference;

import jakarta.ws.rs.core.MultivaluedMap;
import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialModel;
import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialProvider;
import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialProviderFactory;
import nl.wouterh.keycloak.trusteddevice.util.TrustedDeviceToken;
import nl.wouterh.keycloak.trusteddevice.util.UserAgentParser;

@AutoService(RequiredActionFactory.class)
public class RegisterTrustedDeviceAuthenticator implements Authenticator, RequiredActionProvider, RequiredActionFactory {

  private static final SecureRandom secureRandom = new SecureRandom();

  private final KeycloakSession session_;

  public RegisterTrustedDeviceAuthenticator() {
    // required for RequiredActionProvider / RequiredActionFactory
    this.session_ = null;
  }

  public RegisterTrustedDeviceAuthenticator(KeycloakSession session) {
    this.session_ = session;
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getDisplayText() {
    return "Register Trusted Device";
  }

  @Override
  public RequiredActionProvider create(KeycloakSession session) {
    return this;
  }

  @Override
  public List<ProviderConfigProperty> getConfigMetadata() {
    return CONFIG_PROPERTIES;
  }

  private boolean showRegistrationForm(KeycloakSession session, Map<String, String> config, RealmModel realm, UserModel user, LoginFormsProvider form) {
    TrustedDeviceCredentialModel credential = TrustedDeviceToken.getCredentialFromCookie(session, realm, user);

    Duration duration = null;
    boolean passkeyButton = false;
    if (config != null) {
      if (!Strings.isNullOrEmpty(config.get(CONF_DURATION))) {
        duration = Duration.parse(config.get(CONF_DURATION));
      }
      passkeyButton = Boolean.parseBoolean(config.get(CONF_PASSKEY_BUTTON));
    }

    if (credential != null) {
      return false;
    } else {
      form.setAttribute("trustedDeviceName", UserAgentParser.getDeviceName(session))
          .setAttribute("trustedDurationDays", duration.toDays())
          .setAttribute("passkeyButton", passkeyButton);
      return true;
    }
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    RealmModel realm = context.getRealm();

    AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
    Map<String, String> config = null;
    if (authenticatorConfig != null) {
      config = authenticatorConfig.getConfig();
    }

    if (config != null) {
      boolean requiredAction = Boolean.parseBoolean(config.get(CONF_REQUIRED_ACTION));
      if (requiredAction) {
        //context.getAuthenticationSession().addRequiredAction(getId());
        context.getAuthenticationSession().setAuthNote(getId(), "1");

        String jsonSerializedConfig;
        try {
          jsonSerializedConfig = JsonSerialization.writeValueAsString(config);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        context.getAuthenticationSession().setAuthNote(getId() + "-CONFIG", jsonSerializedConfig);

        context.success();
        return;
      }
    }

    LoginFormsProvider form = context.form();
    if(showRegistrationForm(session_, config, realm, user, form)) {
      context.challenge(form.createForm("trusted-device-register.ftl"));
      return;
    }

    context.success();
  }

  @Override
  public void requiredActionChallenge(RequiredActionContext context) {
    UserModel user = context.getUser();
    RealmModel realm = context.getRealm();

    Map<String, String> config = null;
    String jsonSerializedConfig = context.getAuthenticationSession().getAuthNote(getId() + "-CONFIG");
    if (!Strings.isNullOrEmpty(jsonSerializedConfig)) {
      try {
        config = JsonSerialization.readValue(jsonSerializedConfig, new TypeReference<Map<String, String>>() {});
      } catch (IOException e) {
          throw new RuntimeException(e);
      }
    } else {
      RequiredActionProviderModel model = realm.getRequiredActionProviderByAlias(getId());
      RequiredActionConfigModel actionConfig = realm.getRequiredActionConfigByAlias(model.getAlias());
      if (actionConfig != null) {
        config = actionConfig.getConfig();
      }
    }

    LoginFormsProvider form = context.form();
    if(showRegistrationForm(context.getSession(), config, realm, user, form)) {
      context.challenge(form.createForm("trusted-device-register.ftl"));
      return;
    }

    context.success();
  }

  private void performRegistration(KeycloakSession session, Map<String, String> config, RealmModel realm, UserModel user,
      MultivaluedMap<String, String> formParameters, AuthenticationSessionModel authSession, EventBuilder event) {

    TrustedDeviceCredentialModel existingCredential = TrustedDeviceToken.getCredentialFromCookie(session, realm, user);
    if (existingCredential != null) {
      return;
    }

    Duration duration = null;
    if (config != null) {
      if (!Strings.isNullOrEmpty(config.get(CONF_DURATION))) {
        duration = Duration.parse(config.get(CONF_DURATION));
      }
    }

    boolean trustedDevice = "yes".equals(formParameters.getFirst("trusted-device"));
    boolean passkeyButton = "passkey".equals(formParameters.getFirst("trusted-device"));
    boolean trustedCheck = "on".equals(formParameters.getFirst("trusted-check"));
    String deviceName = formParameters.getFirst("trusted-device-name");

    if (trustedCheck && (trustedDevice || passkeyButton) && !Strings.isNullOrEmpty(deviceName)) {
      TrustedDeviceCredentialProvider trustedDeviceCredentialProvider = (TrustedDeviceCredentialProvider) session.getProvider(
          CredentialProvider.class, TrustedDeviceCredentialProviderFactory.PROVIDER_ID);

      // Generate a random 32 byte deviceId
      byte[] bytes = new byte[32];
      secureRandom.nextBytes(bytes);
      String deviceId = Hex.encodeHexString(bytes);

      // Set expiry time in unix epoch time (seconds)
      Long exp = null;
      String credentialName = deviceName;
      if (duration != null) {
        exp = Time.currentTime() + duration.getSeconds();
      }

      TrustedDeviceCredentialModel trustedDeviceCredentialModel = TrustedDeviceCredentialModel.create(
          credentialName, deviceId, exp);

      trustedDeviceCredentialProvider.removeExpiredCredentials(realm, user);

      // Remove any existing credentials with the same device name to handle the case
      // where the user has cleared their cookies but the old credential still exists
      user.credentialManager()
          .getStoredCredentialsByTypeStream(TrustedDeviceCredentialModel.TYPE_TWOFACTOR)
          .filter(cred -> {
            TrustedDeviceCredentialModel model = TrustedDeviceCredentialModel.createFromCredentialModel(cred);
            String existingLabel = model.getUserLabel();
            return deviceName.equals(existingLabel);
          })
          .forEach(cred -> user.credentialManager().removeStoredCredentialById(cred.getId()));

      // Add the new credential
      CredentialModel credential = trustedDeviceCredentialProvider.createCredential(realm, user,
          trustedDeviceCredentialModel);

      event.event(EventType.UPDATE_CREDENTIAL)
          .detail(Details.CREDENTIAL_TYPE, TrustedDeviceCredentialModel.TYPE_TWOFACTOR)
          .detail(Details.CREDENTIAL_USER_LABEL, deviceName)
          .detail(Details.CREDENTIAL_ID, credential.getId());

      int cookieExpirationTime = duration != null ? (int) duration.getSeconds() : Integer.MAX_VALUE;

      TrustedDeviceToken token = new TrustedDeviceToken(credential.getId(), deviceId, exp);
      TrustedDeviceToken.addCookie(session, realm, token, cookieExpirationTime);
    }
    if (passkeyButton) {
      authSession.setClientNote(Constants.KC_ACTION, "webauthn-register-passwordless");
      authSession.setClientNote(Constants.KC_ACTION_EXECUTING, "webauthn-register-passwordless");
      authSession.removeClientNote(Constants.KC_ACTION_ENFORCED);
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    RealmModel realm = context.getRealm();
    EventBuilder event = context.getEvent();

    AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
    Map<String, String> config = null;
    if (authenticatorConfig != null) {
      config = authenticatorConfig.getConfig();
    }

    MultivaluedMap<String, String> formParameters = context.getHttpRequest()
        .getDecodedFormParameters();

    AuthenticationSessionModel authSession = context.getAuthenticationSession();

    performRegistration(session_, config, realm, user, formParameters, authSession, event);

    context.success();
  }

  @Override
  public void processAction(RequiredActionContext context) {
    UserModel user = context.getUser();
    RealmModel realm = context.getRealm();
    EventBuilder event = context.getEvent();

    RequiredActionProviderModel model = realm.getRequiredActionProviderByAlias(getId());
    RequiredActionConfigModel actionConfig = realm.getRequiredActionConfigByAlias(model.getAlias());
    Map<String, String> config = null;
    if (actionConfig != null) {
      config = actionConfig.getConfig();
    }

    MultivaluedMap<String, String> formParameters = context.getHttpRequest()
        .getDecodedFormParameters();

    AuthenticationSessionModel authSession = context.getAuthenticationSession();

    performRegistration(context.getSession(), config, realm, user, formParameters, authSession, event);

    context.success();
  }

  @Override
  public void evaluateTriggers(RequiredActionContext context) {
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    String state = authSession.getAuthNote(getId());
    if (Strings.isNullOrEmpty(state)) {
      return;
    }

    /* check if there is an active/pending AIA (application initiated action / kc_action)
     * if yes, delay registering the required action until after the AIA has completed
     * if no, register the required action immediately
     * I use/fake AIAs for "optional"/cancelable required actions like CONFIGURE_TOTP (in trusted networks)
     * and want the "Register trusted device" dialog to display at the very end
     * (AIA are hard-coded to run last, so just check for that and register our action right after)
     */
    String activeAction = authSession.getClientNote(Constants.KC_ACTION);
    String actionStatus = authSession.getClientNote(Constants.KC_ACTION_STATUS);
    if (state == "1") {
      if (Strings.isNullOrEmpty(activeAction)) {
        authSession.addRequiredAction(getId());
        authSession.removeAuthNote(getId());
      } else {
        authSession.setAuthNote(getId(), "2");
      }
    } else if (state == "2") {
      if (Strings.isNullOrEmpty(activeAction) && "success".equals(actionStatus)) {
        authSession.addRequiredAction(getId());
        authSession.removeAuthNote(getId());
      }
    }
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
  }

  @Override
  public void init(Config.Scope config) {

  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {

  }

  @Override
  public void close() {

  }
}
