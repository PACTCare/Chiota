using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.PageModels.Classes;
using Xamarin.Forms;

namespace Chiota.PageModels.Authentication
{
    public class RegisterPageModel : BasePageModel
    {
        #region Attributes

        private string _name;
        private string _password;

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

        public string Password
        {
            get => _password;
            set
            {
                _password = value;
                OnPropertyChanged(nameof(Password));
            }
        }

        #endregion

        #region ViewIsAppearing

        protected override void ViewIsAppearing()
        {
            base.ViewIsAppearing();

            //Clear the user inputs.
            Name = "";
            Password = "";
        }

        #endregion

        #region Commands

        public ICommand ContinueCommand
        {
            get
            {
                return new Command(() =>
                {
                    if (!string.IsNullOrEmpty(Name) && !string.IsNullOrEmpty(Password))
                    {
                        //Show popup to confirm password.

                        return;
                    }

                    //Show popup alert.
                });
            }
        }

        #endregion
    }
}
