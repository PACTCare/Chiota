using System;
using System.Collections.ObjectModel;
using System.Text;
using System.Windows.Input;

using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Models;
using Chiota.Models.Binding;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Base;
using Xamarin.Forms;

namespace Chiota.ViewModels.Authentication
{
  using Chiota.Views.BackUp;

  /// <summary>
    /// The new seed view model.
    /// </summary>
    public class NewSeedViewModel : BaseViewModel
    {
        #region Attributes

        private bool isDownVisible;
        private bool isSeedViewVisible;
        private bool isUpVisible;

        private SeedBinding seed;
        private int seedLinePointer;

        private Thickness seedViewPadding;
        private ObservableCollection<View> visibleSeedLines;

        #endregion

        #region Properties

        public bool IsDownVisible
        {
            get => isDownVisible;
            set
            {
                isDownVisible = value;
                OnPropertyChanged(nameof(IsDownVisible));
            }
        }

        public bool IsSeedViewVisible
        {
            get => isSeedViewVisible;
            set
            {
                isSeedViewVisible = value;
                OnPropertyChanged(nameof(IsSeedViewVisible));
            }
        }

        public bool IsUpVisible
        {
            get => isUpVisible;
            set
            {
                isUpVisible = value;
                OnPropertyChanged(nameof(IsUpVisible));
            }
        }

        public Thickness SeedViewPadding
        {
            get => seedViewPadding;
            set
            {
                seedViewPadding = value;
                OnPropertyChanged(nameof(SeedViewPadding));
            }
        }

        public ObservableCollection<View> VisibleSeedLines
        {
            get => visibleSeedLines;
            set
            {
                visibleSeedLines = value;
                OnPropertyChanged(nameof(VisibleSeedLines));
            }
        }

        #endregion

        #region Init

        /// <inheritdoc />
        public override void Init(object data = null)
        {
            SeedViewPadding = new Thickness(0, 36, 0, 0);
            base.Init(data);
        }

        #endregion

        #region Commands

        #region Down

        public ICommand DownCommand
        {
            get
            {
                return new Command(() =>
                    {
                        if (seedLinePointer > 8)
                        {
                            return;
                        }

                        seedLinePointer++;
                        IsUpVisible = true;
                        if (seedLinePointer == 8)
                        {
                            IsDownVisible = false;
                            SeedViewPadding = new Thickness(0, 0, 0, 36);
                        }
                        else
                        {
                            SeedViewPadding = new Thickness(0);
                        }

                        UpdateSeedView();
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
                    if (seedLinePointer < 0)
                    {
                        return;
                    }

                    seedLinePointer--;
                    IsDownVisible = true;
                    if (seedLinePointer == 0)
                    {
                        IsUpVisible = false;
                        SeedViewPadding = new Thickness(0, 36, 0, 0);
                    }
                    else
                    {
                        SeedViewPadding = new Thickness(0);
                    }

                    UpdateSeedView();
                });
            }
        }

        #endregion

        #region SeedLetter

        /// <summary>
        /// Gets the seed letter command.
        /// </summary>
        public ICommand SeedLetterCommand
        {
            get
            {
                return new Command(
                    array =>
                    {
                        var items = array as object[];
                        var pointer = (int)items[0];
                        var item = items[1] as Button;

                        if (!(item is Button button))
                        {
                            return;
                        }

                        // Get the seed items random by utf8.
                        var random = new Random();
                        var result = random.Next(65, 91);
                        if (result == 91)
                        {
                            result = 57;
                        }

                        // Update the seed attribute.
                        var resultChar = Encoding.UTF8.GetString(BitConverter.GetBytes(result)).Replace("\0", string.Empty);
                        seed.Lines[seedLinePointer].Items[pointer] = resultChar;
                        button.Text = resultChar;
                    });
            }
        }

        #endregion

        #region GenerateSeed

        public ICommand GenerateSeedCommand
        {
            get
            {
                return new Command(() =>
                {
                    seed = new SeedBinding(Tangle.Net.Entity.Seed.Random().Value);

                    // Reset view.
                    seedLinePointer = 0;
                    IsUpVisible = false;
                    IsDownVisible = true;

                    UpdateSeedView();

                    // Show seed view.
                    IsSeedViewVisible = true;
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
                    // If there exist no seed, show missing seed exception.
                    if (seed == null)
                    {
                        await new AuthMissingSeedException(new ExcInfo()).ShowAlertAsync();
                        return;
                    }

                    await PushAsync<BackUpView>(new UserCreationProperties { Seed = new Tangle.Net.Entity.Seed(ExtractSeed()) });
                });
            }
        }

        #endregion

        #endregion

        #region Methods

        #region ExtractSeed

        /// <summary>
        /// Extract the seed from the view.
        /// Maybe the user changed single characters of the seed,
        /// so we need the actual one.
        /// </summary>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        private string ExtractSeed()
        {
            var result = string.Empty;

            foreach (var line in seed.Lines)
            {
                foreach (var item in line.Items)
                {
                    result += item;
                }
            }

            return result.Length != 81 ? null : result;
        }

        #endregion

        #region UpdateSeedView

        /// <summary>
        /// The update seed view.
        /// TODO: Remove code duplication (see WriteSeedViewModel)
        /// </summary>
        private void UpdateSeedView()
        {
            // Set the pointer for different layouts for the view.
            var enabledPointer = 1;
            if (seedLinePointer == 0)
            {
                enabledPointer = 0;
            }
            else if (seedLinePointer == 8)
            {
                enabledPointer = 2;
            }

            var visibleIndex = 0;
            if (seedLinePointer > 1 && seedLinePointer <= 6)
            {
                visibleIndex = seedLinePointer - 1;
            }
            else if (seedLinePointer > 6)
            {
                visibleIndex = 6;
            }

            var seedLines = seed.Lines.GetRange(visibleIndex, 3);
            var tmp = new ObservableCollection<View>();

            for (var i = 0; i < seedLines.Count; i++)
            {
                var lineView = new StackLayout { Orientation = StackOrientation.Horizontal, Spacing = 2 };

                if (i != enabledPointer)
                {
                    lineView.IsEnabled = false;
                }

                for (var j = 0; j < seedLines[i].Items.Count; j++)
                {
                    var backgroundColor = (Color)Application.Current.Resources["AccentColor"];

                    // Set the layout for every item.
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
                    itemView.CommandParameter = new object[] { j, itemView };

                    if (i != enabledPointer)
                    {
                        itemView.BackgroundColor = Color.FromRgba(backgroundColor.R, backgroundColor.G, backgroundColor.B, 0.6);
                    }

                    lineView.Children.Add(itemView);
                }

                tmp.Add(lineView);
            }

            // Set the new one.
            VisibleSeedLines = tmp;
        }

        #endregion

        #endregion
    }
}