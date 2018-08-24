using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Input;
using Chiota.Models.BackUp;
using Chiota.PageModels.Classes;
using Xamarin.Forms;

namespace Chiota.PageModels.BackUp
{
    public class WriteSeedPageModel : BasePageModel
    {
        #region Attributes

        private Seed _seed;
        private List<SeedLine> _visibleSeedLines;
        private int _seedLinePointer;
        private bool _isUpVisible;
        private bool _isDownVisible;
        private bool _isContinueVisible;
        private Thickness _containerMargin;

        #endregion

        #region Properties

        public List<SeedLine> VisibleSeedLines
        {
            get => _visibleSeedLines;
            set
            {
                _visibleSeedLines = value;
                OnPropertyChanged(nameof(VisibleSeedLines));
            }
        }

        public bool IsUpVisible
        {
            get => _isUpVisible;
            set
            {
                _isUpVisible = value;
                OnPropertyChanged(nameof(IsUpVisible));
            }
        }

        public bool IsDownVisible
        {
            get => _isDownVisible;
            set
            {
                _isDownVisible = value;
                OnPropertyChanged(nameof(IsDownVisible));
            }
        }

        public bool IsContinueVisible
        {
            get => _isContinueVisible;
            set
            {
                _isContinueVisible = value;
                OnPropertyChanged(nameof(IsContinueVisible));
            }
        }

        public Thickness ContainerMargin
        {
            get => _containerMargin;
            set
            {
                _containerMargin = value;
                OnPropertyChanged(nameof(ContainerMargin));
            }
        }

        #endregion

        #region Init

        public override void Init(object data = null)
        {
            base.Init(data);

            //Set the generated iota seed.
            _seed = new Seed(data as string);

            _seedLinePointer = 0;
            VisibleSeedLines = new List<SeedLine>(_seed.Lines.GetRange(_seedLinePointer, 3));
            IsUpVisible = false;
            IsDownVisible = true;
            IsContinueVisible = false;
            ContainerMargin = new Thickness(0, 0, 0, 118);
        }

        #endregion

        #region Commands

        #region UpButton

        public ICommand UpCommand
        {
            get
            {
                return new Command(() =>
                {
                    if (_seedLinePointer > -1)
                    {
                        _seedLinePointer--;
                        IsContinueVisible = false;
                        ContainerMargin = new Thickness(0, 0, 0, 118);
                        IsDownVisible = true;
                        if (_seedLinePointer == 0)
                            //the seed is at the top, up button invisible
                            IsUpVisible = false;
                        VisibleSeedLines = new List<SeedLine>(_seed.Lines.GetRange(_seedLinePointer, 3));
                    }
                });
            }
        }

        #endregion

        #region DownButton

        public ICommand DownCommand
        {
            get
            {
                return new Command(() =>
                {
                    if (_seedLinePointer < _seed.Lines.Count - 2)
                    {
                        _seedLinePointer++;
                        IsUpVisible = true;
                        if (_seedLinePointer == _seed.Lines.Count - 3)
                        {
                            //The seed is at the bottom, down buuton invisible and show button for continue.
                            IsDownVisible = false;
                            ContainerMargin = new Thickness(0, 0, 0, 0);
                            IsContinueVisible = true;
                        }
                        VisibleSeedLines = new List<SeedLine>(_seed.Lines.GetRange(_seedLinePointer, 3));
                    }
                });
            }
        }

        #endregion

        #region ContinueButton

        public ICommand ContinueCommand
        {
            get
            {
                return new Command(async () =>
                {
                    //Go back to back up page.
                    await PopAsync();
                });
            }
        }

        #endregion

        #endregion
    }
}
