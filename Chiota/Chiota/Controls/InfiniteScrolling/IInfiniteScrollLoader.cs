#region References

using System.Threading.Tasks;

#endregion

namespace Chiota.Controls.InfiniteScrolling
{
	public interface IInfiniteScrollLoader
	{
		bool CanLoadMore { get; }

		Task LoadMoreAsync();
	}
}
