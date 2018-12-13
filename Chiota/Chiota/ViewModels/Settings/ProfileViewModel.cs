#region References

using System;
using System.IO;
using System.Windows.Input;
using Chiota.Base;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Popups.PopupModels;
using Chiota.Popups.PopupPageModels;
using Chiota.Popups.PopupPages;
using Chiota.Resources.Localizations;
using Chiota.Resources.Settings;
using Chiota.Services;
using Chiota.Services.DependencyInjection;
using Chiota.Services.Ipfs;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using Plugin.Media;
using Xamarin.Forms;

#endregion

namespace Chiota.ViewModels.Settings
{
    public class ProfileViewModel : BaseViewModel
    {
        #region Attributes

        private ImageSource _profileImageSource;
        private FileImageSource _editImage;
        private string _username;
        private bool _isEdit;
        private bool _isNotEdit;

        private byte[] _imageBuffer;

        private ImageSource _originImageSource;
        private string _originUsername;

        #endregion

        #region Properties

        public ImageSource ProfileImageSource
        {
            get => _profileImageSource;
            set
            {
                _profileImageSource = value;
                OnPropertyChanged(nameof(ProfileImageSource));
            }
        }

        public string Username
        {
            get => _username;
            set
            {
                _username = value;
                OnPropertyChanged(nameof(Username));
            }
        }

        public bool IsEdit
        {
            get => _isEdit;
            set
            {
                _isEdit = value;
                OnPropertyChanged(nameof(IsEdit));
            }
        }

        public bool IsNotEdit
        {
            get => _isNotEdit;
            set
            {
                _isNotEdit = value;
                OnPropertyChanged(nameof(IsNotEdit));
            }
        }

        public FileImageSource EditImage
        {
            get => _editImage;
            set
            {
                _editImage = value;
                OnPropertyChanged(nameof(EditImage));
            }
        }

        #endregion

        #region Init

        public override void Init(object data = null)
        {
            IsEdit = false;
            IsNotEdit = true;

            _originUsername = UserService.CurrentUser.Name;

            if (!string.IsNullOrEmpty(UserService.CurrentUser.ImageBase64))
            {
                //Load the profile image from the loaded buffer of the database.
                var buffer = Convert.FromBase64String(UserService.CurrentUser.ImageBase64);
                _originImageSource = ImageSource.FromStream(() => new MemoryStream(buffer));
            }
            else
                _originImageSource = ImageSource.FromFile("account.png");

            ProfileImageSource = _originImageSource;
            Username = _originUsername;

            base.Init(data);
        }

        #endregion

        #region ViewIsAppearing

        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            EditImage = (FileImageSource)ImageSource.FromFile("edit.png");
        }

        #endregion

        #region Methods

        #region IsChanged

        private bool IsChanged()
        {
            if (Username != _originUsername || ProfileImageSource != _originImageSource)
                return true;
            return false;
        }

        #endregion

        #endregion

        #region Commands

        #region Edit

        public ICommand EditCommand
        {
            get
            {
                return new Command( async () =>
                {
                    IsEdit = !IsEdit;
                    IsNotEdit = !IsEdit;

                    //Set the origin user information.
                    if (!IsEdit)
                    {
                        EditImage = (FileImageSource)ImageSource.FromFile("edit.png");

                        //Set the focus to the page, because of a possible bug.
                        //Otherwise the user can manipulate an input view, if the edit flag is false.
                        //CurrentPage.Unfocus();

                        //Set the changes.
                        /*Username = _originUsername;
                        ProfileImageSource = _originImageSource;*/

                        //Save the changes.
                        //Check if something changed.
                        if (!IsChanged()) return;

                        //Check if the username is set, otherwise set the origin and throw an exception.
                        if (string.IsNullOrEmpty(Username))
                        {
                            await new MissingUserInputException(new ExcInfo(), Details.AuthMissingUserInputName).ShowAlertAsync();
                            Username = _originUsername;
                            IsEdit = false;
                            return;
                        }

                        //Need the password to update the user information.
                        var dialog = new DialogPopupModel()
                        {
                            Title = "Please confirm your password to change your personal information.",
                            Placeholder = AppResources.DlgPassword,
                            IsPassword = true
                        };
                        var result = await DisplayPopupAsync<DialogPopupPageModel, DialogPopupModel>(new DialogPopupPage(), dialog);
                        if (!result.Result)
                        {
                            //Reset the origin data.
                            Username = _originUsername;
                            ProfileImageSource = _profileImageSource;

                            return;
                        }

                        //Show loading popup.
                        await PushLoadingSpinnerAsync("Loading");

                        try
                        {
                            if (_imageBuffer != null)
                            {
                                UserService.CurrentUser.ImagePath = await new IpfsHelper().PostStringAsync(Convert.ToBase64String(_imageBuffer));
                                UserService.CurrentUser.ImageBase64 = Convert.ToBase64String(File.ReadAllBytes(Convert.ToBase64String(_imageBuffer)));
                            }

                            UserService.CurrentUser.Name = Username;

                            var userService = DependencyResolver.Resolve<UserService>();
                            var isValid = await userService.UpdateAsync(result.ResultText, UserService.CurrentUser);
                            if (!isValid)
                            {
                                await PopPopupAsync();
                                await new InvalidUserInputException(new ExcInfo(), AppResources.DlgPassword).ShowAlertAsync();
                                return;
                            }

                            var settings = ApplicationSettings.Load();
                            await settings.Save();

                            DependencyResolver.Reload();

                            await PopPopupAsync();

                            await DisplayAlertAsync("Settings Saved", "The settings got saved successfully");
                            await PopAsync();
                            return;
                        }
                        catch (BaseException exception)
                        {
                            await PopPopupAsync();
                            await exception.ShowAlertAsync();
                        }
                    }
                    else
                        EditImage = (FileImageSource)ImageSource.FromFile("done.png");
                });
            }
        }

        #endregion

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

        #region DeleteAccount

        public ICommand DeleteAccountCommand
        {
            get
            {
                return new Command(async () =>
                {
                    //Show alert for delete informations.
                    var result = await DisplayAlertAsync("Delete account", "Are you sure, you want to delete your account? All of your local data will be lost.", true);

                    if (!result.Result) return;

                    await PushLoadingSpinnerAsync("Delete account ...");

                    var userService = DependencyResolver.Resolve<UserService>();
                    var deleteResult = await userService.DeleteAsync();

                    await PopPopupAsync();

                    if (!deleteResult)
                    {
                        //Could not delete the database. This should not happen.
                        await new UnknownException(new ExcInfo()).ShowAlertAsync();
                    }
                    else
                    {
                        //Show the welcome page.
                        AppBase.ShowStartUp();
                    }
                });
            }
        }

        #endregion

        #endregion
    }
}