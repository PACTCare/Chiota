using System;
using System.Windows.Input;

using Chiota.Annotations;
using Chiota.Classes;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Services.Ipfs;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Classes;
using Chiota.Views;
using Plugin.Media;
using Xamarin.Forms;

namespace Chiota.ViewModels.Authentication
{
    public class SetUserViewModel : BaseViewModel
    {
        #region Attributes

        private string name;
        private double profileImageOpacity;
        private ImageSource profileImageSource;
        private string imagePath;

        private static UserCreationProperties UserProperties;
        private UserService UserService;

        #endregion

        #region Properties

        public string Name
        {
            get => name;
            set
            {
                name = value;
                OnPropertyChanged(nameof(Name));
            }
        }

        public double ProfileImageOpacity
        {
            get => profileImageOpacity;
            set
            {
                profileImageOpacity = value;
                OnPropertyChanged(nameof(ProfileImageOpacity));
            }
        }

        public ImageSource ProfileImageSource
        {
            get => profileImageSource;
            set
            {
                profileImageSource = value;
                OnPropertyChanged(nameof(ProfileImageSource));
            }
        }

        #endregion

        #region Constructors

        public SetUserViewModel(UserService userService)
        {
            UserService = userService;
        }

        #endregion

        #region Init

        /// <inheritdoc />
        public override void Init(object data = null)
        {
            base.Init(data);

            UserProperties = data as UserCreationProperties;

            // Set the default opacity.
            imagePath = string.Empty;
            ProfileImageSource = ImageSource.FromFile("account.png");
            ProfileImageOpacity = 0.6;
        }

        #endregion

        #region ViewIsAppearing

        /// <inheritdoc />
        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            // Clear the user inputs.
            Name = string.Empty;
        }

        #endregion

        #region Commands

        #region ProfileImage

        public ICommand ProfileImageCommand
        {
            get
            {
                return new Command(async () =>
                    {
                        // Open the file explorer of the device and the user choose a image.
                        await CrossMedia.Current.Initialize();

                        if (!CrossMedia.Current.IsPickPhotoSupported)
                            return;

                        var media = await CrossMedia.Current.PickPhotoAsync();
                        if (media?.Path == null)
                            return;

                        try
                        {
                            // Load the image.
                            imagePath = media.Path;
                            ProfileImageSource = ImageSource.FromFile(imagePath);
                            ProfileImageOpacity = 1;
                        }
                        catch (Exception)
                        {
                            await new FailedLoadingFileException(new ExcInfo()).ShowAlertAsync();
                        }
                    });
            }
        }

        #endregion

        #region Continue

        public ICommand ContinueCommand
        {
            get
            {
                return new Command(async () =>
                    {
                        if (string.IsNullOrEmpty(Name))
                        {
                            await new MissingUserInputException(new ExcInfo(), Details.AuthMissingUserInputName).ShowAlertAsync();
                            return;
                        }

                        await PushLoadingSpinnerAsync("Setting up your account");

                        UserProperties.Name = Name;
                        await UserService.CreateNew(UserProperties);

                        if (!string.IsNullOrEmpty(imagePath))
                        {
                            UserService.CurrentUser.ImageHash = await new IpfsHelper().PinFile(imagePath);
                            SecureStorage.UpdateUser(UserProperties.Password);
                        }

                        await PopPopupAsync();

                        AppNavigation.ShowMessenger();
                    });
            }
        }

        #endregion

        #endregion
    }
}