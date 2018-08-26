using System;
using System.Collections.Generic;
using System.Text;

namespace Chiota.Tests
{
  using System.Threading.Tasks;

  using Xamarin.Forms;
    internal class NavigationStub : INavigation
    {
      /// <inheritdoc />
      public void InsertPageBefore(Page page, Page before)
      {
      }

      /// <inheritdoc />
      public Task<Page> PopAsync()
      {
        return null;
      }

      /// <inheritdoc />
      public Task<Page> PopAsync(bool animated)
      {
        return null;
      }

      /// <inheritdoc />
      public Task<Page> PopModalAsync()
      {
        return null;
      }

      /// <inheritdoc />
      public Task<Page> PopModalAsync(bool animated)
      {
        return null;
      }

      /// <inheritdoc />
      public Task PopToRootAsync()
      {
        return null;
      }

      /// <inheritdoc />
      public Task PopToRootAsync(bool animated)
      {
        return null;
      }

      /// <inheritdoc />
      public Task PushAsync(Page page)
      {
        return null;
      }

      /// <inheritdoc />
      public Task PushAsync(Page page, bool animated)
      {
        return null;
      }

      /// <inheritdoc />
      public Task PushModalAsync(Page page)
      {
        return null;
      }

      /// <inheritdoc />
      public Task PushModalAsync(Page page, bool animated)
      {
        return null;
      }

      /// <inheritdoc />
      public void RemovePage(Page page)
      {
      }

      /// <inheritdoc />
      public IReadOnlyList<Page> ModalStack { get; }

      /// <inheritdoc />
      public IReadOnlyList<Page> NavigationStack { get; }
  }
}
