using System;
using Chiota.Resources.Localizations;

#region References

using System.IO;
using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Services;
using Chiota.Services.Ipfs;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using Chiota.Views.Authentication;
using Plugin.Media;
using Xamarin.Forms;

#endregion

namespace Chiota.ViewModels.Authentication
{
    public class SetUserViewModel : BaseViewModel
    {
        #region Attributes

        private string _name;
        private bool _isEntryFocused;
        private ImageSource _profileImageSource;
        private byte[] _imageBuffer;

        private static UserCreationProperties _userProperties;

        #endregion

        #region Properties

        public string Name
        {
            get => _name;
            set
            {
                _name = value;
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
            get => _profileImageSource;
            set
            {
                _profileImageSource = value;
                OnPropertyChanged(nameof(ProfileImageSource));
            }
        }

        #endregion

        #region Init

        /// <inheritdoc />
        public override void Init(object data = null)
        {
            base.Init(data);

            _userProperties = data as UserCreationProperties;
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

                        _imageBuffer = await DependencyService.Get<IImageResizer>().Resize(buffer, 256);

                        try
                        {
                            // Load the image.
                            ProfileImageSource = ImageSource.FromStream(() => new MemoryStream(_imageBuffer));
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

                        _userProperties.Name = Name;

                        await PushLoadingSpinnerAsync(AppResources.DlgLoading);

                        if (_imageBuffer != null)
                        {
                            _userProperties.ImageBase64 = Convert.ToBase64String(_imageBuffer);

                            //Create new ipfs entry with the image data.
                            _userProperties.ImagePath = await new IpfsHelper().PostStringAsync(Convert.ToBase64String(_imageBuffer));
                        }

                        await PopPopupAsync();
                        await PushAsync<SetPasswordView>(_userProperties);
                    });
            }
        }

        #endregion

        #endregion
    }
}