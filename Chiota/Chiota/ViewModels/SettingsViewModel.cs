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
  using Chiota.Services.Iota.Repository;
  using Chiota.Services.Ipfs;
  using Chiota.Services.UserServices;
  using Chiota.ViewModels.Classes;

  using Plugin.Media;
  using Plugin.Media.Abstractions;

  using Xamarin.Forms;

  /// <summary>
  /// The settings view model.
  /// </summary>
  public class SettingsViewModel : BaseViewModel
  {
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

    /// <inheritdoc />
    public SettingsViewModel()
    {
      this.LoadSettings();
    }

    [UsedImplicitly]
    public ICommand SaveCommand => new Command(async () => { await this.SaveSettings(); });

    [UsedImplicitly]
    public ApplicationSettings ApplicationSettings
    {
      get => this.applicationSettings;
      set
      {
        this.applicationSettings = value;
        this.OnPropertyChanged();
      }
    }

    [UsedImplicitly]
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
    public string Username
    {
      get => this.username;
      set
      {
        this.username = value;
        this.OnPropertyChanged();
      }
    }

    public async void SelectImage()
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

    private void LoadSettings()
    {
      this.ApplicationSettings = ApplicationSettings.Load();

      this.ImageSource = ChiotaConstants.IpfsHashGateway + UserService.CurrentUser.ImageHash;
      this.Username = UserService.CurrentUser.Name;
    }

    private async Task SaveSettings()
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

    private async Task SaveApplicationSettings()
    {
      await this.ApplicationSettings.Save();
      DependencyResolver.Reload();

      await this.DisplayAlertAsync("Settings Saved", "The settings got saved successfully");
    }
  }
}