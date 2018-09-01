using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Windows.Input;
using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Models.BackUp;
using Chiota.ViewModels.Classes;
using Chiota.Pages.BackUp;
using Chiota.Services.Iota;
using Xamarin.Forms;

namespace Chiota.ViewModels.Authentication
{
    public class NewSeedViewModel : BaseViewModel
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

            base.Init(data);
        }

        #endregion

        #region Methods

        #region GetNewSeed

        /// <summary>
        /// Returns a new generated iota seed.
        /// </summary>
        /// <returns></returns>
        private string GetNewSeed()
        {
            var seed = Tangle.Net.Entity.Seed.Random();
            return seed.Value;
        }

        #endregion

        #region UpdateSeedView

        private void UpdateSeedView()
        {
            //Set the pointer for different layouts for the view.
            var enabledPointer = 1;
            if (_seedLinePointer == 0)
                enabledPointer = 0;
            else if(_seedLinePointer == 8)
                enabledPointer = 2;

            var visibleIndex = 0;
            if (_seedLinePointer > 1 && _seedLinePointer < 6)
                visibleIndex = _seedLinePointer - 1;
            else if (_seedLinePointer >= 6)
                visibleIndex = 6;

            var seedLines = _seed.Lines.GetRange(visibleIndex, 3);
            var tmp = new ObservableCollection<View>();

            for(var i = 0; i < seedLines.Count; i++)
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
                    var backgroundColor = (Color) Application.Current.Resources["AccentColor"];

                    //Set the layout for every item.
                    var itemView = new Button
                    {
                        TextColor = Color.FromHex("#ffffff"),
                        BackgroundColor = backgroundColor,
                        HeightRequest = 32,
                        WidthRequest = 32,
                        HorizontalOptions = LayoutOptions.Center,
                        VerticalOptions = LayoutOptions.Center,
                        CornerRadius = 8,
                        FontSize = 10,
                        Text = seedLines[i].Items[j],
                        Command = SeedLetterCommand,
                    };
                    itemView.CommandParameter = new object[]{ j, itemView};

                    if (i != enabledPointer)
                        itemView.BackgroundColor = Color.FromRgba(backgroundColor.R, backgroundColor.G, backgroundColor.B, 0.6);

                    lineView.Children.Add(itemView);
                }
                tmp.Add(lineView);
            }

            //Set the new one.
            VisibleSeedLines = tmp;
        }

        #endregion

        #region ExtractSeed

        /// <summary>
        /// Extract the seed from the view.
        /// Maybe the user change single characters of the seed,
        /// so we need the actual one.
        /// </summary>
        /// <returns></returns>
        private string ExtractSeed()
        {
            var result = string.Empty;

            foreach (var line in _seed.Lines)
            {
                foreach (var item in line.Items)
                    result += item;
            }
            return result.Length != 81 ? null : result;
        }

        #endregion

        #endregion

        #region Commands

        #region GenerateSeed

        public ICommand GenerateSeedCommand
        {
            get
            {
                return new Command(() =>
                {
                    _seed = new Seed(GetNewSeed());

                    //Reset view.
                    _seedLinePointer = 0;
                    IsUpVisible = false;
                    IsDownVisible = true;

                    UpdateSeedView();

                    //Show seed view.
                    IsSeedViewVisible = true;
                });
            }
        }

        #endregion

        #region SeedLetter

        public ICommand SeedLetterCommand
        {
            get
            {
                return new Command((array) =>
                {
                    var items = array as object[];
                    var pointer = (int) items[0];
                    var item = items[1] as Button;

                    if(!(item is Button button)) return;

                    //Get the seed items random by utf8.
                    var random = new Random();
                    var result = random.Next(65, 91);
                    if (result == 91)
                        result = 57;

                    //Update the seed attribute.
                    var resultChar = Encoding.UTF8.GetString(BitConverter.GetBytes(result)).Replace("\0", "");
                    _seed.Lines[_seedLinePointer].Items[pointer] = resultChar;
                    button.Text = resultChar;
                });
            }
        }

        #endregion

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
                    //If there exist no seed, show missing seed exception.
                    if (_seed == null)
                    {
                        await new AuthMissingSeedException(new ExcInfo()).ShowAlertAsync();
                        return;
                    }

                    var seed = ExtractSeed();
                    await PushAsync(new BackUpPage(), seed);
                });
            }
        }

        #endregion

        #endregion
    }
}
