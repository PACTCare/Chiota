using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Text;
using System.Windows.Input;
using Chiota.Models.BackUp;
using Chiota.ViewModels.Classes;
using Chiota.Pages.BackUp;
using Xamarin.Forms;

namespace Chiota.ViewModels.BackUp
{
    public class WriteSeedViewModel : BaseViewModel
    {
        #region Attributes

        private Seed _seed;
        private ObservableCollection<View> _visibleSeedLines;

        private Thickness _seedViewPadding;
        private int _seedLinePointer;

        private bool _isSeedViewVisible;
        private bool _isUpVisible;
        private bool _isDownVisible;

        #endregion

        #region Properties

        public ObservableCollection<View> VisibleSeedLines
        {
            get => _visibleSeedLines;
            set
            {
                _visibleSeedLines = value;
                OnPropertyChanged(nameof(VisibleSeedLines));
            }
        }

        public Thickness SeedViewPadding
        {
            get => _seedViewPadding;
            set
            {
                _seedViewPadding = value;
                OnPropertyChanged(nameof(SeedViewPadding));
            }
        }

        public bool IsSeedViewVisible
        {
            get => _isSeedViewVisible;
            set
            {
                _isSeedViewVisible = value;
                OnPropertyChanged(nameof(IsSeedViewVisible));
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

        #endregion

        #region Init

        public override void Init(object data = null)
        {
            SeedViewPadding = new Thickness(0, 36, 0, 0);

            //Reset view.
            _seedLinePointer = 0;
            IsUpVisible = false;
            IsDownVisible = true;

            //Set a new generated seed.
            _seed = new Seed(data as string);
            UpdateSeedView();
            IsSeedViewVisible = true;

            base.Init(data);
        }

        #endregion

        #region Methods

        #region UpdateSeedView

        private void UpdateSeedView()
        {
            var enabledPointer = 1;
            if (_seedLinePointer == 0)
                enabledPointer = 0;
            else if (_seedLinePointer == 8)
                enabledPointer = 2;

            var visibleIndex = 0;
            if (_seedLinePointer > 1 && _seedLinePointer < 6)
                visibleIndex = _seedLinePointer - 1;
            else if (_seedLinePointer >= 6)
                visibleIndex = 6;

            var seedLines = _seed.Lines.GetRange(visibleIndex, 3);
            var tmp = new ObservableCollection<View>();

            for (var i = 0; i < seedLines.Count; i++)
            {
                var lineView = new StackLayout
                {
                    Orientation = StackOrientation.Horizontal,
                    Spacing = 2
                };

                if (i != enabledPointer)
                    lineView.IsEnabled = false;

                for (var j = 0; j < seedLines[i].Items.Count; j++)
                {
                    var backgroundColor = (Color)Application.Current.Resources["AccentColor"];

                    //Set the layout for every item.
                    var itemView = new Label
                    {
                        TextColor = Color.FromHex("#ffffff"),
                        HorizontalOptions = LayoutOptions.Center,
                        VerticalOptions = LayoutOptions.Center,
                        FontSize = 10,
                        Margin = new Thickness(0),
                        Text = seedLines[i].Items[j]
                    };

                    var itemLayout = new Frame
                    {
                        BackgroundColor = backgroundColor,
                        HorizontalOptions = LayoutOptions.Center,
                        VerticalOptions = LayoutOptions.Center,
                        Padding = new Thickness(0),
                        HeightRequest = 32,
                        WidthRequest = 32,
                        CornerRadius = 8,
                        Content = itemView
                    };

                    if (i != enabledPointer)
                        itemLayout.BackgroundColor = Color.FromRgba(backgroundColor.R, backgroundColor.G, backgroundColor.B, 0.6);

                    lineView.Children.Add(itemLayout);
                }
                tmp.Add(lineView);
            }

            //Set the new one.
            VisibleSeedLines = tmp;
        }

        #endregion

        #endregion

        #region Commands

        #region Up

        public ICommand UpCommand
        {
            get
            {
                return new Command(() =>
                {
                    if (_seedLinePointer >= 0)
                    {
                        _seedLinePointer--;
                        IsDownVisible = true;
                        if (_seedLinePointer == 0)
                        {
                            IsUpVisible = false;
                            SeedViewPadding = new Thickness(0, 36, 0, 0);
                        }
                        else
                            SeedViewPadding = new Thickness(0);

                        UpdateSeedView();
                    }
                });
            }
        }

        #endregion

        #region Down

        public ICommand DownCommand
        {
            get
            {
                return new Command(() =>
                {
                    if (_seedLinePointer <= 8)
                    {
                        _seedLinePointer++;
                        IsUpVisible = true;
                        if (_seedLinePointer == 8)
                        {
                            IsDownVisible = false;
                            SeedViewPadding = new Thickness(0, 0, 0, 36);
                        }
                        else
                            SeedViewPadding = new Thickness(0);

                        UpdateSeedView();
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
                    await PopAsync();
                });
            }
        }

        #endregion

        #endregion
    }
}
