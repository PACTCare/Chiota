namespace Chiota.ViewModels
{
  using System;
  using System.Threading.Tasks;
  using System.Windows.Input;

  using Chiota.Annotations;
  using Chiota.Exceptions;
  using Chiota.Extensions;
  using Chiota.Models;
  using Chiota.Popups.PopupModels;
  using Chiota.Popups.PopupPageModels;
  using Chiota.Popups.PopupPages;
  using Chiota.Resources.Settings;
  using Chiota.Services.DependencyInjection;
  using Chiota.Services.Iota;
  using Chiota.Services.Iota.Repository;
  using Chiota.Services.Ipfs;
  using Chiota.Services.UserServices;
  using Chiota.ViewModels.Classes;

  using Plugin.Media;
  using Plugin.Media.Abstractions;

  using Tangle.Net.Entity;
  using Tangle.Net.Repository;

  using Xamarin.Forms;

  /// <summary>
  /// The settings view model.
  /// </summary>
  public class SettingsViewModel : BaseViewModel
  {
    /// <summary>
    /// The display invalid node prompt.
    /// </summary>
    public Action DisplayInvalidNodePrompt;

    /// <summary>
    /// The display settings changed prompt.
    /// </summary>
    public Action DisplaySettingsChangedPrompt;

    /// <summary>
    /// The application settings.
    /// </summary>
    private ApplicationSettings applicationSettings;

    /// <summary>
    /// The image source.
    /// </summary>
    private string imageSource;

    /// <summary>
    /// The media file.
    /// </summary>
    private MediaFile mediaFile;

    /// <summary>
    /// The username.
    /// </summary>
    private string username;

    /// <summary>
    /// Initializes a new instance of the <see cref="SettingsViewModel"/> class.
    /// </summary>
    public SettingsViewModel()
    {
      this.LoadSettings();
    }

    /// <summary>
    /// Gets or sets the application settings.
    /// </summary>
    public ApplicationSettings ApplicationSettings
    {
      get => this.applicationSettings;
      set
      {
        this.applicationSettings = value;
        this.OnPropertyChanged();
      }
    }

    /// <summary>
    /// Gets or sets the image source.
    /// </summary>
    public string ImageSource
    {
      get => this.imageSource;
      set
      {
        this.imageSource = value;
        this.OnPropertyChanged();
      }
    }

    [UsedImplicitly]
    public ICommand PrivacyCommand => new Command(() => { Device.OpenUri(new Uri("https://github.com/Noc2/Chiota/blob/master/PrivacyPolicy.md")); });

    [UsedImplicitly]
    public ICommand SaveCommand => new Command(async () => { await this.SaveSettings(); });

    /// <summary>
    /// Gets or sets the username.
    /// </summary>
    public string Username
    {
      get => this.username;
      set
      {
        this.username = value;
        this.OnPropertyChanged();
      }
    }

    /// <summary>
    /// The add image.
    /// </summary>
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

    /// <summary>
    /// The get settings.
    /// </summary>
    private void LoadSettings()
    {
      this.ApplicationSettings = ApplicationSettings.Load();

      this.ImageSource = ChiotaConstants.IpfsHashGateway + UserService.CurrentUser.ImageHash;
      this.Username = UserService.CurrentUser.Name;
    }

    /// <summary>
    /// The save settings.
    /// </summary>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    private async Task SaveSettings()
    {
      RestIotaRepository node;
      try
      {
        node = RepositoryFactory.GenerateNode(this.ApplicationSettings.DoRemotePoW, this.ApplicationSettings.IotaNodeUri);
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
        if (this.Username != UserService.CurrentUser.Name || this.mediaFile?.Path != null)
        {
          await this.PushPopupAsync<DialogPopupPageModel, DialogPopupModel>(
            new DialogPopupPage(),
            new DialogPopupModel
              {
                Title = "Password required to change name or image.",
                IsPassword = true,
                OkCallback = async (password) =>
                  {
                    try
                    {
                      SecureStorage.ValidatePassword(password);

                      if (this.mediaFile?.Path != null)
                      {
                        UserService.CurrentUser.ImageHash = await new IpfsHelper().PinFile(this.mediaFile.Path);
                        this.mediaFile.Dispose();
                      }

                      UserService.CurrentUser.Name = this.Username;
                      SecureStorage.UpdateUser(password);

                      await this.SaveApplicationSettings();
                    }
                    catch (BaseException exception)
                    {
                      await exception.ShowAlertAsync();
                    }
                  }
              });
        }
        else
        {
          await this.SaveApplicationSettings();
        }
      }
    }

    private async Task SaveApplicationSettings()
    {
      await this.ApplicationSettings.Save();
      DependencyResolver.Reload();

      await this.DisplayAlertAsync("Settings Saved", "The settings got saved successfully");
    }
  }
}