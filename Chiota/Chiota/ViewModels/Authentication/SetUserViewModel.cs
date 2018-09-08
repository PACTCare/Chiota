using System;
using System.Windows.Input;

using Chiota.Annotations;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Classes;
using Chiota.Views;

using Plugin.FilePicker;

using Xamarin.Forms;

namespace Chiota.ViewModels.Authentication
{
    public class SetUserViewModel : BaseViewModel
    {
        #region Attributes

        private string name;
        private double profileImageOpacity;
        private ImageSource profileImageSource;

        private UserCreationProperties UserProperties;
        private UserService UserService;

        #endregion

        #region Properties

        public string Name
        {
            get => this.name;
            set
            {
                this.name = value;
                this.OnPropertyChanged(nameof(this.Name));
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

        #endregion

        #region Constructors

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

        #endregion

        #region Init

        /// <inheritdoc />
        public override void Init(object data = null)
        {
            base.Init(data);

            this.UserProperties = data as UserCreationProperties;

            // Set the default opacity.
            this.ProfileImageSource = ImageSource.FromFile("account.png");
            this.ProfileImageOpacity = 0.6;
        }

        #endregion

        #region ViewIsAppearing

        /// <inheritdoc />
        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            // Clear the user inputs.
            this.Name = string.Empty;
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

        #endregion

        #region Continue

        public ICommand ContinueCommand
        {
            get
            {
                return new Command(async () =>
                    {
                        if (string.IsNullOrEmpty(this.Name))
                        {
                            await new MissingUserInputException(new ExcInfo(), Details.AuthMissingUserInputName).ShowAlertAsync();
                            return;
                        }

                        await this.DisplayLoadingSpinnerAsync("Setting up your account");
                        this.UserProperties.Name = this.Name;
                        await this.UserService.CreateNew(this.UserProperties);
                        await this.PopPopupAsync();

                        Application.Current.MainPage = new NavigationPage(new ContactPage());
                    });
            }
        }

        #endregion

        #endregion
    }
}