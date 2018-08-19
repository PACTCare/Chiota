using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.PageModels.Classes;
using Xamarin.Forms;

namespace Chiota.PageModels.BackUp
{
    public class BackUpPageModel : BasePageModel
    {
        #region Attributes

        private bool _isContinueEnabled;

        #endregion

        #region Properties

        public bool IsContinueEnabled
        {
            get => _isContinueEnabled;
            set
            {
                _isContinueEnabled = value;
                OnPropertyChanged(nameof(IsContinueEnabled));
            }
        }

        #endregion

        #region Commands

        #region Help

        public ICommand HelpCommand
        {
            get
            {
                return new Command(() =>
                {

                });
            }
        }

        #endregion

        #region WriteSeed

        public ICommand WriteSeedCommand
        {
            get
            {
                return new Command(() =>
                {

                });
            }
        }

        #endregion

        #region PrintPaper

        public ICommand PrintPaperCommand
        {
            get
            {
                return new Command(() =>
                {

                });
            }
        }

        #endregion

        #region QrCode

        public ICommand QrCodeCommand
        {
            get
            {
                return new Command(() =>
                {

                });
            }
        }

        #endregion

        #region Continue

        public ICommand ContinueCommand
        {
            get
            {
                return new Command(() =>
                {

                });
            }
        }

        #endregion

        #endregion
    }
}
