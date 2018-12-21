#region References

using Chiota.Persistence;
using Autofac;

using Chiota.Droid.Services;
using Chiota.Services;

using Pact.Palantir.Cache;
using Pact.Palantir.Repository;

#endregion

namespace Chiota.Droid
{
    /// <inheritdoc />
    public class InjectionModule : Module
    {
        /// <inheritdoc />
        protected override void Load(ContainerBuilder builder)
        {
            builder.RegisterType<TransactionCacheRepository>().As<ITransactionCache>();
            builder.RegisterType<ContactRepository>().As<IContactRepository>().PropertiesAutowired();
        }
    }
}
