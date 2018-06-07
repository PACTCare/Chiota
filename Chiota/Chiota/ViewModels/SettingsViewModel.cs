namespace Chiota.ViewModels
{
  using System;
  using System.Windows.Input;

  using Chiota.IOTAServices;
  using Chiota.Models;

  using RestSharp;

  using Tangle.Net.Repository;
  using Tangle.Net.Repository.Client;

  using Xamarin.Forms;

  public class SettingsViewModel : BaseViewModel
  {
    public Action DisplayInvalidNodePrompt;

    public Action DisplaySettingsChangedPrompt;

    private readonly User user;

    private bool remotePoW = true;

    private string defaultNode = "https://field.carriota.com:443";

    public SettingsViewModel(User user)
    {
      this.GetSettings();
      this.user = user;
      this.SaveCommand = new Command(this.SaveSettings);
      this.PrivacyCommand = new Command(this.OpenPrivacyPolicy);
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

    public ICommand SaveCommand { get; set; }

    public ICommand PrivacyCommand { get; set; }

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

    private void SaveSettings()
    {
      RestIotaRepository node;
      try
      {
        var iotaClient = new RestIotaClient(new RestClient(this.DefaultNode));
        node = RepositoryFactory.GenerateNode(this.RemotePow, iotaClient);
      }
      catch
      {
        node = null;
      }

      if (node == null || !NodeTest.NodeIsHealthy(node))
      {
        this.DisplayInvalidNodePrompt();
      }
      else
      {
        Application.Current.Properties[ChiotaConstants.SettingsNodeKey] = this.DefaultNode;
        Application.Current.Properties[ChiotaConstants.SettingsPowKey] = this.RemotePow;
        this.user.TangleMessenger = new TangleMessenger(this.user.Seed);
        this.DisplaySettingsChangedPrompt();
      }
    }
  }
}
