﻿namespace Chiota.ViewModels.Authentication
{
  using System;
  using System.Windows.Input;

  using Chiota.Exceptions;
  using Chiota.Extensions;
  using Chiota.Services.UserServices;
  using Chiota.ViewModels.Classes;
  using Chiota.Views;

  using Plugin.FilePicker;

  using Xamarin.Forms;

  /// <summary>
  /// The set user view model.
  /// </summary>
  public class SetUserViewModel : BaseViewModel
  {
    private string name;

    private double profileImageOpacity;

    private ImageSource profileImageSource;

    /// <summary>
    /// Initializes a new instance of the <see cref="SetUserViewModel"/> class.
    /// </summary>
    /// <param name="userService">
    /// The user service.
    /// </param>
    public SetUserViewModel(UserService userService)
    {
      this.UserService = userService;
    }

    public ICommand ContinueCommand
    {
      get
      {
        return new Command(
          async () =>
            {
              if (!string.IsNullOrEmpty(this.Name))
              {
                await this.DisplayLoadingSpinnerAsync("Setting up your account");
                this.UserProperties.Name = this.Name;
                await this.UserService.CreateNew(this.UserProperties);
                await this.PopPopupAsync();

                Application.Current.MainPage = new ContactPage();
                return;
              }

              await new MissingUserInputException(new ExcInfo(), Details.AuthMissingUserInputName).ShowAlertAsync();
            });
      }
    }

    public string Name
    {
      get => this.name;
      set
      {
        this.name = value;
        this.OnPropertyChanged(nameof(this.Name));
      }
    }

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

    public double ProfileImageOpacity
    {
      get => this.profileImageOpacity;
      set
      {
        this.profileImageOpacity = value;
        this.OnPropertyChanged(nameof(this.ProfileImageOpacity));
      }
    }

    public ImageSource ProfileImageSource
    {
      get => this.profileImageSource;
      set
      {
        this.profileImageSource = value;
        this.OnPropertyChanged(nameof(this.ProfileImageSource));
      }
    }

    private UserCreationProperties UserProperties { get; set; }

    private UserService UserService { get; }

    /// <inheritdoc />
    public override void Init(object data = null)
    {
      base.Init(data);

      this.UserProperties = data as UserCreationProperties;

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