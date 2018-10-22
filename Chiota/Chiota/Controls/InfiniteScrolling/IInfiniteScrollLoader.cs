using System.Threading.Tasks;

namespace Chiota.Controls.InfiniteScrolling
{
	public interface IInfiniteScrollLoader
	{
		bool CanLoadMore { get; }

		Task LoadMoreAsync();
	}
}
