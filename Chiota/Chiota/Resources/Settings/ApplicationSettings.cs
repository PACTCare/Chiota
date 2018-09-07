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
    public const string DefaultNode = "https://field.deviota.com:443";

    private ApplicationSettings()
    {
    }

    public bool DoRemotePoW { get; set; }

    public string IotaNodeUri { get; set; }

    public static ApplicationSettings Load()
    {
      var node = Application.Current.Properties[ChiotaConstants.SettingsNodeKey] as string;
      node = string.IsNullOrEmpty(node) ? DefaultNode : node;

      return new ApplicationSettings
               {
                 DoRemotePoW = Application.Current.Properties[ChiotaConstants.SettingsPowKey] as bool? == true, IotaNodeUri = node
               };
    }

    public async Task Save()
    {
      Application.Current.Properties[ChiotaConstants.SettingsPowKey] = this.DoRemotePoW;
      Application.Current.Properties[ChiotaConstants.SettingsNodeKey] = this.IotaNodeUri;
      await Application.Current.SavePropertiesAsync();
    }
  }
}