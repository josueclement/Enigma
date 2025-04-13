using System.Windows.Controls;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Enigma.WpfApp.Controls;

public abstract class NavigationPageBase : Page
{
    private readonly ILogger<NavigationPageBase> _logger = App.Services.GetRequiredService<ILogger<NavigationPageBase>>();

    public virtual void OnAppeared()
    {
        _logger.LogTrace("OnAppeared: {type}", GetType().Name);
    }

    public virtual void OnDisappeared()
    {
        _logger.LogTrace("OnDisappeared: {type}", GetType().Name);
    }
}