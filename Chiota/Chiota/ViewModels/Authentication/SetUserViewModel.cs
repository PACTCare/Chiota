using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Input;

using Chiota.Annotations;
using Chiota.Base;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Resources.Localizations;
using Chiota.Services;
using Chiota.Services.DependencyInjection;
using Chiota.Services.Ipfs;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using Chiota.Views;
using Chiota.Views.Authentication;
using Plugin.Media;
using Plugin.Media.Abstractions;
using Xamarin.Forms;

namespace Chiota.ViewModels.Authentication
{
    public class SetUserViewModel : BaseViewModel
    {
        #region Attributes

        private string name;
        private bool _isEntryFocused;
        private ImageSource profileImageSource;
        private byte[] imageBuffer;

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

        public bool IsEntryFocused
        {
            get => _isEntryFocused;
            set
            {
                _isEntryFocused = value;
                OnPropertyChanged(nameof(IsEntryFocused));
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
            ProfileImageSource = ImageSource.FromFile("account.png");
        }

        #endregion

        #region ViewIsAppearing

        /// <inheritdoc />
        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            Device.BeginInvokeOnMainThread(async () =>
            {
                //Focus the entry.
                await Task.Delay(TimeSpan.FromMilliseconds(500));
                IsEntryFocused = true;
            });
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

                        //Take an image.
                        var media = await CrossMedia.Current.PickPhotoAsync();

                        if (media?.Path == null)
                            return;

                        //Resize the image.
                        var stream = media.GetStream();
                        var buffer = new byte[stream.Length];
                        stream.Read(buffer, 0, buffer.Length);

                        imageBuffer = await DependencyService.Get<IImageResizer>().Resize(buffer, 256);

                        try
                        {
                            // Load the image.
                            ProfileImageSource = ImageSource.FromStream(() => new MemoryStream(imageBuffer));
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

                        UserProperties.Name = Name;

                        if(imageBuffer != null)
                            UserProperties.ImageBase64 = Convert.ToBase64String(imageBuffer);

                        await PushAsync<SetPasswordView>(UserProperties);
                    });
            }
        }

        #endregion

        #endregion
    }
}