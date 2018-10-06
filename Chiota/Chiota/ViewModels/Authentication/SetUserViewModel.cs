using System;
using System.IO;
using System.Windows.Input;

using Chiota.Annotations;
using Chiota.Base;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Resources.Localizations;
using Chiota.Services.DependencyInjection;
using Chiota.Services.Ipfs;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using Chiota.Views;
using Plugin.Media;
using Xamarin.Forms;

namespace Chiota.ViewModels.Authentication
{
    public class SetUserViewModel : BaseViewModel
    {
        #region Attributes

        private string name;
        private ImageSource profileImageSource;
        private string imagePath;
        private Stream imageStream;

        private static UserCreationProperties UserProperties;

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

        #region Init

        /// <inheritdoc />
        public override void Init(object data = null)
        {
            base.Init(data);

            UserProperties = data as UserCreationProperties;

            // Set the default opacity.
            imagePath = string.Empty;
            ProfileImageSource = ImageSource.FromFile("account.png");
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
                            imageStream = media.GetStream();
                            ProfileImageSource = ImageSource.FromFile(imagePath);
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

                        await PushLoadingSpinnerAsync(AppResources.DlgSettingUpAccount);

                        UserProperties.Name = Name;

                        if (!string.IsNullOrEmpty(imagePath) && imageStream != null)
                        {
                            //Pin the image to ipfs.
                            UserProperties.ImageHash = await new IpfsHelper().PinFile(imagePath);

                            //Load the image local.
                            var buffer = new byte[imageStream.Length];
                            imageStream.Read(buffer, 0, buffer.Length);
                            UserProperties.ImageBase64 = Convert.ToBase64String(buffer);
                        }

                        var userService = DependencyResolver.Resolve<UserService>();
                        var result = await userService.CreateNew(UserProperties);
                        
                        await PopPopupAsync();

                        if (!result)
                        {
                            await new UnknownException(new ExcInfo()).ShowAlertAsync();
                            await AppBase.ShowStartUpAsync();
                            return;
                        }

                        AppBase.ShowMessenger();
                    });
            }
        }

        #endregion

        #endregion
    }
}