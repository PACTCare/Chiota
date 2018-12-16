#region References

using System.Collections.ObjectModel;
using System.Windows.Input;
using Chiota.Models.Binding;
using Chiota.ViewModels.Base;
using Xamarin.Forms;

#endregion

namespace Chiota.ViewModels.BackUp
{
    public class WriteSeedViewModel : BaseViewModel
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

        public override void Init(object data = null)
        {
            SeedViewPadding = new Thickness(0, 36, 0, 0);

            // Reset view.
            seedLinePointer = 0;
            IsUpVisible = false;
            IsDownVisible = true;

            // Set a new generated seed.
            seed = new SeedBinding(data as string);
            UpdateSeedView();
            IsSeedViewVisible = true;

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

        #region Continue

        public ICommand ContinueCommand => new Command(async () => { await PopAsync(); });

        #endregion

        #endregion

        #region Methods

        #region UpdateSeedView

        /// <summary>
        /// The update seed view.
        /// TODO: Remove code duplication (see NewSeedViewModel)
        /// </summary>
        private void UpdateSeedView()
        {
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
                    {
                        itemLayout.BackgroundColor = Color.FromRgba(backgroundColor.R, backgroundColor.G, backgroundColor.B, 0.6);
                    }

                    lineView.Children.Add(itemLayout);
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