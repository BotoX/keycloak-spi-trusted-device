package nl.wouterh.keycloak.trusteddevice.authenticator;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import com.google.auto.service.AutoService;

import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialModel;

@AutoService(AuthenticatorFactory.class)
public class RegisterTrustedDeviceAuthenticatorFactory implements AuthenticatorFactory {

  public static final String CONF_DURATION = "duration";
  public static final String CONF_PASSKEY_BUTTON = "passkey-button";
  public static final String CONF_REQUIRED_ACTION = "required-action";

  public static final String PROVIDER_ID = "trusted-device-authenticator";

  public static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<ProviderConfigProperty>();

  static {
    ProviderConfigProperty duration = new ProviderConfigProperty();
    duration.setType(ProviderConfigProperty.STRING_TYPE);
    duration.setName(CONF_DURATION);
    duration.setLabel("Trust duration");
    duration.setDefaultValue("");
    duration.setHelpText(
        "Duration the device will be trusted. Input format is a Java Duration, for example P365d or PT24h. Empty value means forever.");
    CONFIG_PROPERTIES.add(duration);

    ProviderConfigProperty passkeyButton = new ProviderConfigProperty();
    passkeyButton.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    passkeyButton.setName(CONF_PASSKEY_BUTTON);
    passkeyButton.setLabel("Add Passkey Registration");
    passkeyButton.setDefaultValue(Boolean.toString(false));
    passkeyButton.setHelpText(
        "Add a Passkey Registration button to the bottom of the form");
    CONFIG_PROPERTIES.add(passkeyButton);
  }

  @Override
  public String getDisplayType() {
    return "Register Trusted Device";
  }

  @Override
  public String getReferenceCategory() {
    return TrustedDeviceCredentialModel.TYPE_TWOFACTOR;
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return true;
  }

  @Override
  public String getHelpText() {
    return "Prompts the user if they want to trust their device. Use 'Condition - Credential Configured' to check if the device is trusted.";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    List<ProviderConfigProperty> config = new ArrayList<>(CONFIG_PROPERTIES);

    ProviderConfigProperty requiredAction = new ProviderConfigProperty();
    requiredAction.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    requiredAction.setName(CONF_REQUIRED_ACTION);
    requiredAction.setLabel("Required Action");
    requiredAction.setDefaultValue(Boolean.toString(false));
    requiredAction.setHelpText(
        "Act as a required action instead of an authenticator");
    config.add(requiredAction);

    return config;
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return new RegisterTrustedDeviceAuthenticator(session);
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

  @Override
  public String getId() {
    return PROVIDER_ID;
  }
}
