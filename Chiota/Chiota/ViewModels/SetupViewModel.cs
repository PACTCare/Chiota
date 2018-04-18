namespace Chiota.ViewModels
{
  using System;
  using System.Threading.Tasks;
  using System.Windows.Input;

  using Chiota.Models;
  using Chiota.Services;
  using Chiota.Views;

  using Newtonsoft.Json;

  using Plugin.Media;
  using Plugin.Media.Abstractions;

  using Tangle.Net.Entity;
  using Tangle.Net.Utils;

  using Xamarin.Forms;

  public class SetupViewModel : BaseViewModel
  {
    public Action DisplayInvalidLoginPrompt;

    private string username;

    private string imageSource;

    private MediaFile mediaFile;

    public SetupViewModel(User user)
    {
      this.ImageSource = "https://chiota.blob.core.windows.net/userimages/default.png";
      user.ImageUrl = this.ImageSource;
      this.SubmitCommand = new Command(async () => { await this.FinishedSetup(user); });
    }

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

    private async Task FinishedSetup(User user)
    {
      if (this.Username == string.Empty)
      {
        this.DisplayInvalidLoginPrompt();
      }
      else if (!this.AlreadyClicke)
      {
        this.IsBusy = true;
        this.AlreadyClicke = true;
        user.Name = this.Username;

        if (this.mediaFile?.Path != null)
        {
          user.ImageUrl = await new BlobStorage().UploadToBlob(user.PublicKeyAddress, this.mediaFile.Path);
        }

        user = await this.StoreDataOnTangle(user);

        if (user.StoreSeed)
        {
          new SecureStorage().StoreUser(user);
        }

        this.IsBusy = false;
        this.AlreadyClicke = false;

        Application.Current.MainPage = new NavigationPage(new ContactPage(user));
        await this.Navigation.PopToRootAsync(true);
      }
    }

    private async Task<User> StoreDataOnTangle(User user)
    {
      var publicKeyTrytes = user.NtruChatPair.PublicKey.ToBytes().ToTrytes();

      var userData = new UserFactory().CreateUploadUser(user);
      var serializeObject = JsonConvert.SerializeObject(userData);
     
      await this.SendParallelAsync(user, publicKeyTrytes, TryteString.FromUtf8String(serializeObject));
      return user;
    }

    private Task SendParallelAsync(User user, TryteString publicKeyTrytes, TryteString mamEncrypted)
    {
      var firstTransaction = user.TangleMessenger.SendMessageAsync(new TryteString(mamEncrypted + ChiotaIdentifier.End), user.OwnDataAdress);

      // only way to store it with one transaction, json to big
      var requestAdressTrytes = new TryteString(publicKeyTrytes + ChiotaIdentifier.LineBreak + user.RequestAddress + ChiotaIdentifier.End);

      var secondTransaction = user.TangleMessenger.SendMessageAsync(requestAdressTrytes, user.PublicKeyAddress);
      return Task.WhenAll(firstTransaction, secondTransaction);
    }
  }
}