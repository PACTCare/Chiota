#region References

using System;

#endregion

namespace Chiota.Controls.InfiniteScrolling
{
	public interface IInfiniteScrollLoading
	{
		bool IsLoadingMore { get; }

		event EventHandler<LoadingMoreEventArgs> LoadingMore;
	}
}
