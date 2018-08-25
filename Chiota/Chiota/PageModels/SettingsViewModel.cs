using Chiota.PageModels.Classes;
using Chiota.ViewModels.Classes;

namespace Chiota.ViewModels
{
  using System;
  using System.Threading.Tasks;
  using System.Windows.Input;

  using Chiota.Models;
  using Chiota.Services.Iota;
  using Chiota.Services.Iota.Repository;
  using Chiota.Services.Ipfs;
  using Chiota.Services.UserServices;

  using Plugin.Media;
  using Plugin.Media.Abstractions;

  using Tangle.Net.Repository;

  using Xamarin.Forms;

  public class SettingsViewModel : BasePageModel
    {
    public Action DisplayInvalidNodePrompt;

    public Action DisplaySettingsChangedPrompt;

    private bool remotePoW = true;

    private string username;

    private string imageSource;

    private MediaFile mediaFile;

    private string defaultNode = "https://field.deviota.com:443";

    public SettingsViewModel()
    {
      this.GetSettings();
    }

    public string Username
    {
      get => this.username;
      set
      {
        this.username = value;
        this.OnPropertyChanged();
      }
    }

    public string ImageSource
    {
      get => this.imageSource;
      set
      {
        this.imageSource = value;
        this.OnPropertyChanged();
      }
    }

    public bool RemotePow
    {
      get => this.remotePoW;
      set
      {
        this.remotePoW = value;
        this.OnPropertyChanged();
      }
    }

    public string DefaultNode
    {
      get => this.defaultNode;
      set
      {
        this.defaultNode = value;
        this.OnPropertyChanged();
      }
    }

    public ICommand SaveCommand => new Command(async () => { await this.SaveSettings(); });

    public ICommand PrivacyCommand => new Command(this.OpenPrivacyPolicy);

    public async void AddImage()
    {
      await CrossMedia.Current.Initialize();

      if (!CrossMedia.Current.IsPickPhotoSupported)
      {
        return;
      }

      this.mediaFile = await CrossMedia.Current.PickPhotoAsync();
      if (this.mediaFile?.Path != null)
      {
        this.ImageSource = this.mediaFile.Path;
      }
    }

    private void GetSettings()
    {
      var remote = Application.Current.Properties[ChiotaConstants.SettingsPowKey] as bool?;
      this.RemotePow = remote == true;
      this.DefaultNode = Application.Current.Properties[ChiotaConstants.SettingsNodeKey] as string;
      this.ImageSource = ChiotaConstants.IpfsHashGateway + Application.Current.Properties[ChiotaConstants.SettingsImageKey + UserService.CurrentUser.PublicKeyAddress] as string;
      this.Username = Application.Current.Properties[ChiotaConstants.SettingsNameKey + UserService.CurrentUser.PublicKeyAddress] as string;
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
        if (this.mediaFile?.Path != null)
        {
          //var imageStream = await ImageService.Instance
          //                    .LoadFile(this.mediaFile.Path)
          //                    .DownSample(300)
          //                    .AsJPGStreamAsync();

          UserService.CurrentUser.ImageHash = await new IpfsHelper().PinFile(this.mediaFile.Path);
          this.mediaFile.Dispose();
        }

        Application.Current.Properties[ChiotaConstants.SettingsImageKey + UserService.CurrentUser.PublicKeyAddress] = UserService.CurrentUser.ImageHash;
        Application.Current.Properties[ChiotaConstants.SettingsNameKey + UserService.CurrentUser.PublicKeyAddress] = this.Username;
        Application.Current.Properties[ChiotaConstants.SettingsNodeKey] = this.DefaultNode;
        Application.Current.Properties[ChiotaConstants.SettingsPowKey] = this.RemotePow;
        await Application.Current.SavePropertiesAsync();
        UserService.CurrentUser.TangleMessenger = new TangleMessenger(UserService.CurrentUser.Seed);
        this.DisplaySettingsChangedPrompt();
      }
    }
  }
}
