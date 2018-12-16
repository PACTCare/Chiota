#region References

using System;
using System.Threading.Tasks;
using System.Windows.Input;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Services;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using Plugin.Media;
using Tangle.Net.Utils;
using Xamarin.Forms;

#endregion

namespace Chiota.ViewModels.BackUp
{
  using Chiota.Views.Authentication;

  public class ConfirmSeedViewModel : BaseViewModel
    {
        #region Attributes

        private string seed;
        private bool _isEntryFocused;
        private ImageSource _validationImageSource;
        private Keyboard _keyboard;

        private UserCreationProperties UserProperties;

        #endregion

        #region Properties

        public string Seed
        {
            get => seed;
            set
            {
                seed = value;
                OnPropertyChanged(nameof(Seed));
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

        public ImageSource ValidationImageSource
        {
            get => _validationImageSource;
            set
            {
                _validationImageSource = value;
                OnPropertyChanged(nameof(ValidationImageSource));
            }
        }

        public Keyboard Keyboard
        {
            get => _keyboard;
            set
            {
                _keyboard = value;
                OnPropertyChanged(nameof(Keyboard));
            }
        }

        #endregion

        #region Init

        /// <inheritdoc />
        public override void Init(object data = null)
        {
            base.Init(data);
            UserProperties = data as UserCreationProperties;

            Keyboard = Keyboard.Create(KeyboardFlags.CapitalizeCharacter);
        }

        #endregion

        #region ViewIsAppearing

        /// <inheritdoc />
        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            // Clear the user inputs.
            Seed = string.Empty;

            Device.BeginInvokeOnMainThread(async () =>
            {
                //Focus the entry.
                await Task.Delay(TimeSpan.FromMilliseconds(500));
                IsEntryFocused = true;
            });
        }

        #endregion

        #region Commands

        #region IsValid

        public ICommand IsValidCommand
        {
            get
            {
                return new Command((param) =>
                {
                    var isValid = (bool)param;

                    if (isValid)
                        ValidationImageSource = ImageSource.FromFile("done.png");
                    else if (!string.IsNullOrEmpty(Seed))
                        ValidationImageSource = ImageSource.FromFile("clear.png");
                    else
                        ValidationImageSource = null;
                });
            }
        }

        #endregion

        #region OpenQrCode

        public ICommand OpenQrCodeCommand
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

                    Seed = await DependencyService.Get<IImageQrCodeReader>().ReadAsync(buffer);
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
                    if (!string.IsNullOrEmpty(Seed))
                    {
                        if (!InputValidator.IsTrytes(Seed))
                        {
                            await new InvalidUserInputException(new ExcInfo(), Details.BackUpInvalidUserInputSeed).ShowAlertAsync();
                            return;
                        }

                        if (Seed != UserProperties.Seed.Value)
                        {
                            await new BackUpFailedSeedConfirmationException(new ExcInfo()).ShowAlertAsync();
                            return;
                        }

                        await PushAsync<SetUserView>(UserProperties);
                        return;
                    }

                    await new MissingUserInputException(new ExcInfo(), Details.BackUpInvalidUserInputSeed).ShowAlertAsync();
                });
            }
        }

        #endregion

        #endregion
    }
}