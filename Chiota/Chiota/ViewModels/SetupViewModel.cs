namespace Chiota.ViewModels
{
  using System;
  using System.IO;
  using System.Threading.Tasks;
  using System.Windows.Input;

  using Chiota.Models;
  using Chiota.Services;
  using Chiota.Views;

  using Newtonsoft.Json;

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
      else if (!this.AlreadyClicked)
      {
        this.IsBusy = true;
        this.AlreadyClicked = true;
        user.Name = this.Username;

        if (this.mediaFile?.Path != null)
        {
          var imageAsBytes = await this.GenerateByteImage(this.mediaFile);

          imageAsBytes = await DependencyService.Get<IResizeService>().ResizeImage(imageAsBytes, 350, 350);

          user.ImageUrl = await new BlobStorage().UploadToBlob(Helper.ImageNameGenerator(user.Name, user.PublicKeyAddress), this.mediaFile.Path, imageAsBytes);
          this.mediaFile.Dispose();
        }

        user = await this.StoreDataOnTangle(user);

        if (user.StoreSeed)
        {
          new SecureStorage().StoreUser(user);
        }

        this.IsBusy = false;
        this.AlreadyClicked = false;

        Application.Current.MainPage = new NavigationPage(new ContactPage(user));
        await this.Navigation.PopToRootAsync(true);
      }
    }

    private async Task<byte[]> GenerateByteImage(MediaFile methodeMediaFile)
    {
      byte[] imageAsBytes;
      using (var memoryStream = new MemoryStream())
      {
        await methodeMediaFile.GetStream().CopyToAsync(memoryStream);
        imageAsBytes = memoryStream.ToArray();
      }

      return imageAsBytes;
    }

    private async Task<User> StoreDataOnTangle(User user)
    {
      var publicKeyTrytes = user.NtruChatPair.PublicKey.ToBytes().EncodeBytesAsString();

      var userData = new UserFactory().CreateUploadUser(user);
      var serializeObject = JsonConvert.SerializeObject(userData);

      await this.SendParallelAsync(user, new TryteString(publicKeyTrytes), serializeObject);
      return user;
    }

    private Task SendParallelAsync(User user, TryteString publicKeyTrytes, string serializeObject)
    {
      var encryptedAccept = new NtruKex().Encrypt(user.NtruContactPair.PublicKey, serializeObject);
      var firstTransaction = user.TangleMessenger.SendMessageAsync(new TryteString(encryptedAccept.EncodeBytesAsString() + ChiotaConstants.End), user.OwnDataAdress);

      // only way to store it with one transaction, json too big
      var requestAdressTrytes = new TryteString(publicKeyTrytes + ChiotaConstants.LineBreak + user.RequestAddress + ChiotaConstants.End);

      var secondTransaction = user.TangleMessenger.SendMessageAsync(requestAdressTrytes, user.PublicKeyAddress);
      return Task.WhenAll(firstTransaction, secondTransaction);
    }
  }
}