using Chiota.Droid.Persistence;
using Chiota.Persistence;

namespace Chiota.Droid
{
  using Autofac;

  using Chiota.Droid.Services;
  using Chiota.Messenger.Cache;
  using Chiota.Messenger.Repository;
  using Chiota.Services;

  /// <inheritdoc />
  public class InjectionModule : Module
  {
    /// <inheritdoc />
    protected override void Load(ContainerBuilder builder)
    {
      builder.RegisterType<ClipboardService>().As<IClipboardService>();

        builder.RegisterType<SqlLiteTransactionCache>().As<ITransactionCache>();
        builder.RegisterType<SqlLiteTransactionCache>().As<AbstractSqlLiteTransactionCache>();

        builder.RegisterType<SqlLiteContactRepository>().As<IContactRepository>().PropertiesAutowired();
        builder.RegisterType<SqlLiteContactRepository>().As<AbstractSqlLiteContactRepository>().PropertiesAutowired();
        }
  }
}
