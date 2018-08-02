using Chiota.ViewModels.Classes;

namespace Chiota.ViewModels
{
  using System;
  using System.Threading.Tasks;
  using System.Windows.Input;

  using Chiota.Events;
  using Chiota.Models;
  using Chiota.Services;
  using Chiota.Services.DependencyInjection;
  using Chiota.Services.Ipfs;
  using Chiota.Services.Navigation;
  using Chiota.Services.Storage;
  using Chiota.Services.UserServices;

  using Plugin.Media;
  using Plugin.Media.Abstractions;

  using Tangle.Net.Entity;

  using Xamarin.Forms;

  public class SetupViewModel : BaseViewModel
  {
    public Action DisplayInvalidLoginPrompt;

    private string username;

    private string imageSource;

    private MediaFile mediaFile;

    public SetupViewModel(User user)
    {
      this.ImageSource = ChiotaConstants.IpfsHashGateway + Application.Current.Properties[ChiotaConstants.SettingsImageKey + user.PublicKeyAddress];
      this.Username = Application.Current.Properties[ChiotaConstants.SettingsNameKey + user.PublicKeyAddress] as string;
      user.ImageHash = Application.Current.Properties[ChiotaConstants.SettingsImageKey + user.PublicKeyAddress] as string;
      this.SubmitCommand = new Command(async () => { await this.FinishedSetup(user); });
    }

    /// <summary>
    /// Event raised as soon as the setup process has been completed. Subscribe if you want to react to that.
    /// Outputs EventArgs of type <see cref="SetupEventArgs"/>
    /// </summary>
    public static event EventHandler SetupCompleted;

    public string Username
    {
      get => this.username;
      set
      {
        this.username = value;
        this.RaisePropertyChanged();
      }
    }

    public string ImageSource
    {
      get => this.imageSource;
      set
      {
        this.imageSource = value;
        this.RaisePropertyChanged();
      }
    }

    public ICommand SubmitCommand { get; protected set; }

    public async void AddImage()
    {
      await CrossMedia.Current.Initialize();

      if (!CrossMedia.Current.IsPickPhotoSupported)
      {
        // await this.DisplayAlert("Error", "Select an image", "Ok");
        return;
      }

      this.mediaFile = await CrossMedia.Current.PickPhotoAsync();
      if (this.mediaFile?.Path != null)
      {
        this.ImageSource = this.mediaFile.Path;
      }
    }

    private static async Task StorePublicKeyOnTangle(User user)
    {
      var publicKeyTrytes = user.NtruKeyPair.PublicKey.ToBytes().EncodeBytesAsString();
      var requestAdressTrytes = new TryteString(publicKeyTrytes + ChiotaConstants.LineBreak + user.RequestAddress + ChiotaConstants.End);
      await user.TangleMessenger.SendMessageAsync(requestAdressTrytes, user.PublicKeyAddress);
    }

    private static async Task StoreUserData(User user)
    {
      Application.Current.Properties[ChiotaConstants.SettingsImageKey + user.PublicKeyAddress] = user.ImageHash;
      Application.Current.Properties[ChiotaConstants.SettingsNameKey + user.PublicKeyAddress] = user.Name;
      await Application.Current.SavePropertiesAsync();
    }

    private async Task FinishedSetup(User user)
    {
      if (this.Username == string.Empty)
      {
        this.DisplayInvalidLoginPrompt();
      }
      else if (!this.IsBusy)
      {
        this.IsBusy = true;
        user.Name = this.Username;

        if (this.mediaFile?.Path != null)
        {
          //var imageStream = await ImageService.Instance
          //               .LoadFile(this.mediaFile.Path)
          //               .DownSample(300)
          //               .AsJPGStreamAsync();
          user.ImageHash = await new IpfsHelper().PinFile(this.mediaFile.Path);
          this.mediaFile.Dispose();
        }

        await StoreUserData(user);
        await StorePublicKeyOnTangle(user);
        new SecureStorage().StoreUser(user);

        // Fire setup completed event to allow consumers to add behaviour
        SetupCompleted?.Invoke(this, new SetupEventArgs { User = user });
        UserService.SetCurrentUser(user);

        this.IsBusy = false;

        Application.Current.MainPage = new NavigationPage(DependencyResolver.Resolve<INavigationService>().LoggedInEntryPoint);
        await this.Navigation.PopToRootAsync(true);
      }
    }
  }
}