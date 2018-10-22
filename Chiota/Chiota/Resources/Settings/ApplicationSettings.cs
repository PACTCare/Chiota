using Chiota.Helper;

namespace Chiota.Resources.Settings
{
  using System.Threading.Tasks;

  using Chiota.Models;

  using Xamarin.Forms;

  /// <summary>
  /// The application settings.
  /// </summary>
  public class ApplicationSettings
  {
    private ApplicationSettings()
    {
    }

    public bool DoRemotePoW { get; set; }

    public string IotaNodeUri { get; set; }

    public static ApplicationSettings Load()
    {
      var node = Application.Current.Properties.ContainsKey(ChiotaConstants.SettingsNodeKey)
                   ? Application.Current.Properties[ChiotaConstants.SettingsNodeKey] as string
                   : "https://field.deviota.com:443";

      var remotePoW = Application.Current.Properties.ContainsKey(ChiotaConstants.SettingsPowKey)
                        ? Application.Current.Properties[ChiotaConstants.SettingsPowKey] as bool?
                        : true;

      return new ApplicationSettings { DoRemotePoW = remotePoW == true, IotaNodeUri = node };
    }

    public async Task Save()
    {
      Application.Current.Properties[ChiotaConstants.SettingsPowKey] = DoRemotePoW;
      Application.Current.Properties[ChiotaConstants.SettingsNodeKey] = IotaNodeUri;
      await Application.Current.SavePropertiesAsync();
    }
  }
}