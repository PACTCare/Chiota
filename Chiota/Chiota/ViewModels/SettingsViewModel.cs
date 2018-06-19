namespace Chiota.ViewModels
{
  using System;
  using System.Threading.Tasks;
  using System.Windows.Input;

  using Chiota.IOTAServices;
  using Chiota.Models;
  using Chiota.Services.Iota.Repository;
  using Chiota.Services.UserServices;

  using RestSharp;

  using Tangle.Net.Repository;
  using Tangle.Net.Repository.Client;

  using Xamarin.Forms;

  public class SettingsViewModel : BaseViewModel
  {
    public Action DisplayInvalidNodePrompt;

    public Action DisplaySettingsChangedPrompt;

    private bool remotePoW = true;

    private string defaultNode = "https://field.carriota.com:443";

    public SettingsViewModel()
    {
      this.GetSettings();
    }

    public bool RemotePow
    {
      get => this.remotePoW;
      set
      {
        this.remotePoW = value;
        this.RaisePropertyChanged();
      }
    }

    public string DefaultNode
    {
      get => this.defaultNode;
      set
      {
        this.defaultNode = value;
        this.RaisePropertyChanged();
      }
    }

    public ICommand SaveCommand => new Command(async () => { await this.SaveSettings(); });

    public ICommand PrivacyCommand => new Command(this.OpenPrivacyPolicy);

    public void GetSettings()
    {
      if (Application.Current.Properties.ContainsKey(ChiotaConstants.SettingsPowKey))
      {
        var remote = Application.Current.Properties[ChiotaConstants.SettingsPowKey] as bool?;
        this.RemotePow = remote == true;
        this.DefaultNode = Application.Current.Properties[ChiotaConstants.SettingsNodeKey] as string;
      }
    }

    private void OpenPrivacyPolicy()
    {
      Device.OpenUri(new Uri("https://github.com/Noc2/Chiota/blob/master/PrivacyPolicy.md"));
    }

    private async Task SaveSettings()
    {
      RestIotaRepository node;
      try
      {
        node = RepositoryFactory.GenerateNode(this.RemotePow, this.DefaultNode);
      }
      catch
      {
        node = null;
      }

      if (node == null || !RepositoryFactory.NodeIsHealthy(node))
      {
        this.DisplayInvalidNodePrompt();
      }
      else
      {
        Application.Current.Properties[ChiotaConstants.SettingsNodeKey] = this.DefaultNode;
        Application.Current.Properties[ChiotaConstants.SettingsPowKey] = this.RemotePow;
        await Application.Current.SavePropertiesAsync();
        UserService.CurrentUser.TangleMessenger = new TangleMessenger(UserService.CurrentUser.Seed);
        this.DisplaySettingsChangedPrompt();
      }
    }
  }
}
