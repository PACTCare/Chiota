using System;
using System.Collections.ObjectModel;
using System.Text;
using System.Windows.Input;

using Chiota.Exceptions;
using Chiota.Extensions;
using Chiota.Models;
using Chiota.Services.UserServices;
using Chiota.ViewModels.Classes;

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

        private SeedView seed;
        private int seedLinePointer;

        private Thickness seedViewPadding;
        private ObservableCollection<View> visibleSeedLines;

        #endregion

        #region Properties

        public bool IsDownVisible
        {
            get => this.isDownVisible;
            set
            {
                this.isDownVisible = value;
                this.OnPropertyChanged(nameof(this.IsDownVisible));
            }
        }

        public bool IsSeedViewVisible
        {
            get => this.isSeedViewVisible;
            set
            {
                this.isSeedViewVisible = value;
                this.OnPropertyChanged(nameof(this.IsSeedViewVisible));
            }
        }

        public bool IsUpVisible
        {
            get => this.isUpVisible;
            set
            {
                this.isUpVisible = value;
                this.OnPropertyChanged(nameof(this.IsUpVisible));
            }
        }

        public Thickness SeedViewPadding
        {
            get => this.seedViewPadding;
            set
            {
                this.seedViewPadding = value;
                this.OnPropertyChanged(nameof(this.SeedViewPadding));
            }
        }

        public ObservableCollection<View> VisibleSeedLines
        {
            get => this.visibleSeedLines;
            set
            {
                this.visibleSeedLines = value;
                this.OnPropertyChanged(nameof(this.VisibleSeedLines));
            }
        }

        #endregion

        #region Init

        /// <inheritdoc />
        public override void Init(object data = null)
        {
            this.SeedViewPadding = new Thickness(0, 36, 0, 0);
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
                        if (this.seedLinePointer > 8)
                        {
                            return;
                        }

                        this.seedLinePointer++;
                        this.IsUpVisible = true;
                        if (this.seedLinePointer == 8)
                        {
                            this.IsDownVisible = false;
                            this.SeedViewPadding = new Thickness(0, 0, 0, 36);
                        }
                        else
                        {
                            this.SeedViewPadding = new Thickness(0);
                        }

                        this.UpdateSeedView();
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
                    if (this.seedLinePointer < 0)
                    {
                        return;
                    }

                    this.seedLinePointer--;
                    this.IsDownVisible = true;
                    if (this.seedLinePointer == 0)
                    {
                        this.IsUpVisible = false;
                        this.SeedViewPadding = new Thickness(0, 36, 0, 0);
                    }
                    else
                    {
                        this.SeedViewPadding = new Thickness(0);
                    }

                    this.UpdateSeedView();
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
                        this.seed.Lines[this.seedLinePointer].Items[pointer] = resultChar;
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
                    this.seed = new SeedView(Tangle.Net.Entity.Seed.Random().Value);

                    // Reset view.
                    this.seedLinePointer = 0;
                    this.IsUpVisible = false;
                    this.IsDownVisible = true;

                    this.UpdateSeedView();

                    // Show seed view.
                    this.IsSeedViewVisible = true;
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
                    if (this.seed == null)
                    {
                        await new AuthMissingSeedException(new ExcInfo()).ShowAlertAsync();
                        return;
                    }

                    await this.PushAsync(new BackUpView(), new UserCreationProperties { Seed = new Tangle.Net.Entity.Seed(this.ExtractSeed()) });
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

            foreach (var line in this.seed.Lines)
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
            if (this.seedLinePointer == 0)
            {
                enabledPointer = 0;
            }
            else if (this.seedLinePointer == 8)
            {
                enabledPointer = 2;
            }

            var visibleIndex = 0;
            if (this.seedLinePointer > 1 && this.seedLinePointer <= 6)
            {
                visibleIndex = this.seedLinePointer - 1;
            }
            else if (this.seedLinePointer > 6)
            {
                visibleIndex = 6;
            }

            var seedLines = this.seed.Lines.GetRange(visibleIndex, 3);
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
                        Command = this.SeedLetterCommand,
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
            this.VisibleSeedLines = tmp;
        }

        #endregion

        #endregion
    }
}