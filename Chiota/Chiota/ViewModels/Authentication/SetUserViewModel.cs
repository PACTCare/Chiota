namespace Chiota.ViewModels.Authentication
{
  using System;
  using System.Windows.Input;

  using Chiota.Exceptions;
  using Chiota.Extensions;
  using Chiota.ViewModels.Classes;
  using Chiota.Views;

  using Plugin.FilePicker;

  using Xamarin.Forms;

  /// <summary>
  /// The set user view model.
  /// </summary>
  public class SetUserViewModel : BaseViewModel
  {
    /// <summary>
    /// The _name.
    /// </summary>
    private string name;

    /// <summary>
    /// The _profile image opacity.
    /// </summary>
    private double profileImageOpacity;

    /// <summary>
    /// The _profile image source.
    /// </summary>
    private ImageSource profileImageSource;

    /// <summary>
    /// Gets the continue command.
    /// </summary>
    public ICommand ContinueCommand
    {
      get
      {
        return new Command(
          async () =>
            {
              if (!string.IsNullOrEmpty(this.Name))
              {
                await this.PushAsync(new ContactPage());
                return;
              }

              await new MissingUserInputException(new ExcInfo(), Details.AuthMissingUserInputName).ShowAlertAsync();
            });
      }
    }

    /// <summary>
    /// Gets or sets the name.
    /// </summary>
    public string Name
    {
      get => this.name;
      set
      {
        this.name = value;
        this.OnPropertyChanged(nameof(this.Name));
      }
    }

    /// <summary>
    /// Gets the profile image command.
    /// </summary>
    public ICommand ProfileImageCommand
    {
      get
      {
        return new Command(
          async () =>
            {
              // Open the file explorer of the device and the user choose a image.
              var fileData = await CrossFilePicker.Current.PickFile();
              if (fileData == null)
              {
                return;
              }

              try
              {
                // Load the image.
                this.ProfileImageSource = ImageSource.FromStream(() => fileData.GetStream());
                this.ProfileImageOpacity = 1;
              }
              catch (Exception)
              {
                await new FailedLoadingFileException(new ExcInfo()).ShowAlertAsync();
              }
            });
      }
    }

    /// <summary>
    /// Gets or sets the profile image opacity.
    /// </summary>
    public double ProfileImageOpacity
    {
      get => this.profileImageOpacity;
      set
      {
        this.profileImageOpacity = value;
        this.OnPropertyChanged(nameof(this.ProfileImageOpacity));
      }
    }

    /// <summary>
    /// Gets or sets the profile image source.
    /// </summary>
    public ImageSource ProfileImageSource
    {
      get => this.profileImageSource;
      set
      {
        this.profileImageSource = value;
        this.OnPropertyChanged(nameof(this.ProfileImageSource));
      }
    }

    /// <inheritdoc />
    public override void Init(object data = null)
    {
      base.Init(data);

      // Set the default opacity.
      this.ProfileImageSource = ImageSource.FromFile("account.png");
      this.ProfileImageOpacity = 0.6;
    }

    /// <inheritdoc />
    protected override void ViewIsAppearing()
    {
      base.ViewIsAppearing();

      // Clear the user inputs.
      this.Name = string.Empty;
    }
  }
}