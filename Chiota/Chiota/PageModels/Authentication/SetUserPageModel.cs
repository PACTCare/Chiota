using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.PageModels.Classes;
using ImageCircle.Forms.Plugin.Abstractions;
using Plugin.FilePicker;
using Plugin.FilePicker.Abstractions;
using Xamarin.Forms;

namespace Chiota.PageModels.Authentication
{
    public class SetUserPageModel : BasePageModel
    {
        #region Attributes

        private string _name;
        private double _profileImageOpacity;
        private ImageSource _profileImageSource;

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

        public double ProfileImageOpacity
        {
            get => _profileImageOpacity;
            set
            {
                _profileImageOpacity = value;
                OnPropertyChanged(nameof(ProfileImageOpacity));
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

        public override void Init(object data = null)
        {
            base.Init(data);

            //Set the default opacity.
            ProfileImageSource = ImageSource.FromFile("account.png");
            ProfileImageOpacity = 0.6;
        }

        #endregion

        #region ViewIsAppearing

        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            //Clear the user inputs.
            Name = "";
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
                    //Open the file explorer of the device and the user choose a image.
                    var fileData = await CrossFilePicker.Current.PickFile();
                    if (fileData == null)
                        return;

                    try
                    {
                        //Load the image.
                        var stream = fileData.GetStream();
                        ProfileImageSource = ImageSource.FromStream(() => stream);
                        ProfileImageOpacity = 1;
                    }
                    catch (Exception)
                    {
                        await new FailedLoadingFileException(new ExcInfo()).ShowAlertAsync();
                        return;
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
                    if (!string.IsNullOrEmpty(Name))
                    {
                        //TODO Navigate to the contact page.
                        //await PushAsync(new RegisterPage());
                        return;
                    }

                    await new MissingUserInputException(new ExcInfo(), "name").ShowAlertAsync();
                });
            }
        }

        #endregion

        #endregion
    }
}
